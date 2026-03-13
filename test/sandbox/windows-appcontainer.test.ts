import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  existsSync,
  readFileSync,
  readdirSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import net from 'node:net'

import { getPlatform } from '../../src/utils/platform.js'
import {
  wrapCommandWithSandboxWindows,
  getAppContainerHelperPath,
  sweepStaleAppContainerState,
  cleanupWindowsConfigFiles,
  checkWindowsDependencies,
} from '../../src/sandbox/windows-sandbox-utils.js'

const isWindows = getPlatform() === 'windows'
const helperAvailable = isWindows && getAppContainerHelperPath() !== null

/**
 * Unit-level smoke tests that verify wrapCommandWithSandboxWindows produces
 * the expected config file and command string. These run on any platform
 * (they don't execute the helper).
 *
 * Integration tests that actually spawn into an AppContainer require Windows
 * AND the helper binary to be built. They're gated on helperAvailable.
 */

describe('windows-sandbox-utils: unit', () => {
  it('returns command unchanged when nothing to restrict', async () => {
    const cmd = 'echo hello'
    const wrapped = await wrapCommandWithSandboxWindows({
      command: cmd,
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: undefined,
    })
    expect(wrapped).toBe(cmd)
  })

  it('checkWindowsDependencies reports missing helper on non-Windows', () => {
    if (isWindows) return
    const deps = checkWindowsDependencies()
    // On macOS/Linux, the .exe won't exist
    expect(deps.errors.length).toBeGreaterThan(0)
    expect(deps.errors[0]).toContain('srt-appcontainer.exe')
  })

  it('sweepStaleAppContainerState is a no-op when helper is missing', () => {
    if (helperAvailable) return
    // Should not throw even with no helper
    expect(() => sweepStaleAppContainerState()).not.toThrow()
  })
})

describe('windows-sandbox-utils: config generation', () => {
  if (!isWindows) {
    it.skip('requires Windows', () => {})
    return
  }

  let testDir: string

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'srt-test-'))
  })

  afterEach(() => {
    cleanupWindowsConfigFiles()
    rmSync(testDir, { recursive: true, force: true })
  })

  it('writes a config JSON and returns helper invocation', async () => {
    if (!helperAvailable) return

    const wrapped = await wrapCommandWithSandboxWindows({
      command: 'echo hello',
      needsNetworkRestriction: true,
      httpProxyPort: 3128,
      socksProxyPort: 1080,
      readConfig: undefined,
      writeConfig: { allowOnly: [testDir], denyWithinAllow: [] },
    })

    expect(wrapped).toContain('srt-appcontainer.exe')
    expect(wrapped).toContain('--config')

    // Extract config path from the wrapped command: "<helper>" --config "<path>"
    const configMatch = wrapped.match(/--config\s+"([^"]+)"/)
    expect(configMatch).not.toBeNull()
    const configPath = configMatch![1]
    expect(existsSync(configPath)).toBe(true)

    const cfg = JSON.parse(readFileSync(configPath, 'utf-8'))
    expect(cfg.profileName).toMatch(/^srt-[0-9a-f]{16}$/)
    expect(cfg.allowWrite).toContain(testDir)
    expect(cfg.needsNetworkRestriction).toBe(true)
    expect(cfg.env.some((e: string) => e.startsWith('HTTP_PROXY='))).toBe(true)
    expect(
      cfg.env.some((e: string) => e.startsWith('ALL_PROXY=socks5h://')),
    ).toBe(true)
    expect(cfg.command).toContain('cmd.exe')
    expect(cfg.command).toContain('echo hello')
    expect(cfg.sidecarPath).toMatch(/srt-[0-9a-f]{16}\.aclstate$/)
  })

  it('includes denyWithinAllow paths in denyRead', async () => {
    if (!helperAvailable) return

    const secretFile = join(testDir, 'secret.txt')
    writeFileSync(secretFile, 'shh')

    const wrapped = await wrapCommandWithSandboxWindows({
      command: 'type secret.txt',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: [testDir], denyWithinAllow: [secretFile] },
    })

    const configMatch = wrapped.match(/--config\s+"([^"]+)"/)
    const cfg = JSON.parse(readFileSync(configMatch![1], 'utf-8'))
    expect(cfg.denyRead).toContain(secretFile)
  })

  it('cleanupWindowsConfigFiles removes pending config files', async () => {
    if (!helperAvailable) return

    const wrapped = await wrapCommandWithSandboxWindows({
      command: 'echo hello',
      needsNetworkRestriction: true,
      readConfig: undefined,
      writeConfig: undefined,
    })
    const configMatch = wrapped.match(/--config\s+"([^"]+)"/)
    const configPath = configMatch![1]
    expect(existsSync(configPath)).toBe(true)

    cleanupWindowsConfigFiles()
    expect(existsSync(configPath)).toBe(false)
  })
})

describe('windows-appcontainer: integration', () => {
  if (!helperAvailable) {
    it.skip('requires Windows with built helper binary', () => {})
    return
  }

  let testDir: string

  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), 'srt-int-'))
  })

  afterEach(() => {
    cleanupWindowsConfigFiles()
    rmSync(testDir, { recursive: true, force: true })
  })

  function runWrapped(wrapped: string): {
    code: number
    stdout: string
    stderr: string
  } {
    const result = spawnSync(wrapped, { shell: true, encoding: 'utf-8' })
    return {
      code: result.status ?? -1,
      stdout: result.stdout ?? '',
      stderr: result.stderr ?? '',
    }
  }

  describe('filesystem', () => {
    it('allows write inside allowWrite', async () => {
      const targetFile = join(testDir, 'out.txt')
      // Use cmd.exe builtin — node.exe is in a user-profile directory that
      // the AppContainer cannot read (no ALL APPLICATION PACKAGES SID).
      const cmd = `echo ok>"${targetFile}"`

      const wrapped = await wrapCommandWithSandboxWindows({
        command: cmd,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [testDir], denyWithinAllow: [] },
      })

      const { code } = runWrapped(wrapped)
      expect(code).toBe(0)
      expect(existsSync(targetFile)).toBe(true)
      expect(readFileSync(targetFile, 'utf-8')).toContain('ok')
    })

    it('blocks write outside allowWrite', async () => {
      // Write to a second temp dir NOT in allowWrite.
      const otherDir = mkdtempSync(join(tmpdir(), 'srt-other-'))
      const targetFile = join(otherDir, 'blocked.txt')
      try {
        // Use cmd.exe builtin — node.exe is inaccessible from AppContainer.
        const cmd = `echo x>"${targetFile}"`

        const wrapped = await wrapCommandWithSandboxWindows({
          command: cmd,
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig: { allowOnly: [testDir], denyWithinAllow: [] },
        })

        const { code, stderr } = runWrapped(wrapped)
        expect(code).toBe(1)
        expect(stderr).toMatch(/Access is denied|EACCES|EPERM/)
        expect(existsSync(targetFile)).toBe(false)
      } finally {
        rmSync(otherDir, { recursive: true, force: true })
      }
    })

    it('blocks read on denyRead paths', async () => {
      const secretFile = join(testDir, 'secret.txt')
      writeFileSync(secretFile, 'shh')

      // Use cmd.exe builtin — node.exe is inaccessible from AppContainer.
      const cmd = `type "${secretFile}"`

      const wrapped = await wrapCommandWithSandboxWindows({
        command: cmd,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [secretFile] },
        writeConfig: { allowOnly: [testDir], denyWithinAllow: [] },
      })

      const { code, stdout, stderr } = runWrapped(wrapped)
      expect(code).toBe(1)
      expect(stdout).not.toContain('shh')
      expect(stderr).toMatch(/Access is denied|EACCES|EPERM/)
    })

    it('denies write to .git/config inside allowWrite (mandatory deny)', async () => {
      // Set up a fake .git/config under cwd (the ripgrep scan roots at cwd)
      const gitDir = join(process.cwd(), '.git')
      const gitConfig = join(gitDir, 'config')
      if (!existsSync(gitConfig)) {
        // Can't test without a real .git/config; skip gracefully
        return
      }

      // Use cmd.exe builtin — node.exe is inaccessible from AppContainer.
      const cmd = `echo.>>"${gitConfig}"`

      const wrapped = await wrapCommandWithSandboxWindows({
        command: cmd,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [process.cwd()], denyWithinAllow: [] },
        allowGitConfig: false,
      })

      const { code } = runWrapped(wrapped)
      expect(code).toBe(1)
    })
  })

  describe('network', () => {
    it('blocks direct TCP connect without internetClient', async () => {
      // curl ships in System32 on Win10 1803+. PATH-resolved, not absolute —
      // LowBox tokens strip SeChangeNotifyPrivilege, so cmd.exe's unquoted-
      // absolute-path probe (GetFileAttributesW) dies at C:\ traversal
      // (drive root has no ALL APPLICATION PACKAGES ACE). PATH resolution
      // skips the probe and CreateProcess succeeds. PowerShell fails even
      // with all that solved — its init touches inaccessible profile dirs.
      const cmd = `curl --connect-timeout 3 -sS http://1.1.1.1/`

      const wrapped = await wrapCommandWithSandboxWindows({
        command: cmd,
        needsNetworkRestriction: true,
        readConfig: undefined,
        writeConfig: { allowOnly: [testDir], denyWithinAllow: [] },
      })

      const { code, stderr } = runWrapped(wrapped)
      // curl without internetClient: connect() → WSAEACCES → exit 7.
      // The exit code is the invariant; stderr phrasing varies by curl build.
      expect(code).not.toBe(0)
      expect(stderr.toLowerCase()).toContain('connect')
    })

    // AC→host loopback is blocked by AppContainer network isolation.
    // The named-pipe bridge (srt-appcontainer.cpp:489) tunnels proxy
    // traffic through pipes (filesystem DACLs, not subject to network
    // isolation); its intra-AC loopback invariant is proven by
    // spike-intraloop.exe. NetworkIsolationSetAppContainerConfig would
    // bypass this but requires admin — the bridge is the non-admin path.
    it('blocks loopback to a host-side listener (no bridge, no exemption)', async () => {
      const server = net.createServer(sock => {
        sock.write('pong')
        sock.end()
      })
      await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
      const port = (server.address() as net.AddressInfo).port

      try {
        const cmd = `curl --connect-timeout 2 -sS http://127.0.0.1:${port}/`

        const wrapped = await wrapCommandWithSandboxWindows({
          command: cmd,
          needsNetworkRestriction: true,
          readConfig: undefined,
          writeConfig: { allowOnly: [testDir], denyWithinAllow: [] },
        })

        const { code } = runWrapped(wrapped)
        // No proxy ports → no pipe bridge → no exemption → blocked.
        // curl exit 28 (timeout) or 7 (couldn't connect).
        expect(code).not.toBe(0)
      } finally {
        server.close()
      }
    })

    // TODO: end-to-end test of the pipe bridge. Set httpProxyPort to a
    // host-side listener, verify curl with HTTP_PROXY reaches it through
    // the bridge. Requires the forwarder binary to be built.
  })

  describe('ACL lifecycle', () => {
    /**
     * Run icacls on a path and return SIDs of AppContainer ACEs (S-1-15-2-*).
     * AppContainer SIDs always start with S-1-15-2- (the well-known app
     * package authority).
     */
    function getAppContainerSids(path: string): string[] {
      const result = spawnSync('icacls', [path], { encoding: 'utf-8' })
      if (result.status !== 0) return []
      const sids: string[] = []
      for (const match of result.stdout.matchAll(/S-1-15-2-[\d-]+/g)) {
        sids.push(match[0])
      }
      return sids
    }

    it('leaves no stale ACLs after clean exit', async () => {
      const before = getAppContainerSids(testDir)

      const wrapped = await wrapCommandWithSandboxWindows({
        command: 'echo done',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [testDir], denyWithinAllow: [] },
      })

      const { code } = runWrapped(wrapped)
      expect(code).toBe(0)

      const after = getAppContainerSids(testDir)
      // No new AppContainer SIDs should have been added
      expect(after.length).toBe(before.length)
    })

    it('leaves no stale sidecar after clean exit', async () => {
      const wrapped = await wrapCommandWithSandboxWindows({
        command: 'echo done',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [testDir], denyWithinAllow: [] },
      })

      // Peek at the config to find the sidecar path
      const configMatch = wrapped.match(/--config\s+"([^"]+)"/)
      const cfg = JSON.parse(readFileSync(configMatch![1], 'utf-8'))
      const sidecarPath = cfg.sidecarPath

      const { code } = runWrapped(wrapped)
      expect(code).toBe(0)
      expect(existsSync(sidecarPath)).toBe(false)
    })

    it('sweepStaleAppContainerState cleans up simulated crash', async () => {
      // Simulate a crash: manually write a sidecar that points to a real
      // profile + ACL. We let the helper create everything, then kill it
      // mid-run by using a long-running command and terminating early.
      //
      // Simpler approach: use the helper's --config to set everything up
      // with a command that sleeps, then TerminateProcess it. But that's
      // fiddly from bun. Even simpler: manually construct a sidecar file
      // pointing to a SID that doesn't exist and a path that does, then
      // verify sweep removes the sidecar (the ACL removal will be a no-op
      // since the SID was never granted, which is fine).

      const fakeSidecarPath = join(tmpdir(), `srt-${'0'.repeat(16)}.aclstate`)
      // Format: profileName\nSID\nop|path\n (UTF-16LE)
      const sidecarContent = `srt-${'0'.repeat(16)}\nS-1-15-2-1-2-3-4-5-6-7\nG|${testDir}\n`
      writeFileSync(fakeSidecarPath, Buffer.from(sidecarContent, 'utf16le'))

      expect(existsSync(fakeSidecarPath)).toBe(true)
      sweepStaleAppContainerState()
      expect(existsSync(fakeSidecarPath)).toBe(false)
    })

    it('stale sidecars from real crash are swept on next init', async () => {
      // Count sidecars before
      const sidecarsBefore = readdirSync(tmpdir()).filter(
        f => f.startsWith('srt-') && f.endsWith('.aclstate'),
      ).length

      // Spawn a long-running sandboxed child. Use Bun.spawn (async) so we
      // can check for the sidecar DURING execution, before the helper has a
      // chance to clean up. A cmd.exe for-loop is used because external
      // executables (ping, timeout, choice) fail inside the AppContainer.
      const wrapped = await wrapCommandWithSandboxWindows({
        command: 'for /l %i in (1,1,999999999) do @rem',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [testDir], denyWithinAllow: [] },
      })

      // Extract helper path and config path from the wrapped command
      const helperMatch = wrapped.match(/^"([^"]+)"\s+--config\s+"([^"]+)"$/)
      if (!helperMatch) {
        throw new Error('Cannot parse wrapped command: ' + wrapped)
      }
      const child = Bun.spawn([helperMatch[1], '--config', helperMatch[2]], {
        stdout: 'pipe',
        stderr: 'pipe',
      })

      // Wait for the helper to set up ACLs and write the sidecar
      await new Promise(r => setTimeout(r, 3000))

      // Now there should be at least one more sidecar
      const sidecarsMid = readdirSync(tmpdir()).filter(
        f => f.startsWith('srt-') && f.endsWith('.aclstate'),
      ).length
      expect(sidecarsMid).toBeGreaterThan(sidecarsBefore)

      // Kill the process tree (simulates a crash)
      child.kill()
      await new Promise(r => setTimeout(r, 1000))

      // Sweep
      sweepStaleAppContainerState()

      // Back to baseline (or fewer, if there were pre-existing ones)
      const sidecarsAfter = readdirSync(tmpdir()).filter(
        f => f.startsWith('srt-') && f.endsWith('.aclstate'),
      ).length
      expect(sidecarsAfter).toBeLessThanOrEqual(sidecarsBefore)

      // And the ACL on testDir should be back to baseline too
      const sids = getAppContainerSids(testDir)
      // All srt-created SIDs gone (this is a fresh temp dir, so 0 expected)
      expect(sids.length).toBe(0)
    })
  })
})
