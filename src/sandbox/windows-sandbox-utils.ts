import { randomBytes } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  existsSync,
  readdirSync,
  writeFileSync,
  rmSync,
  mkdirSync,
  realpathSync,
} from 'node:fs'
import { execFileSync } from 'node:child_process'

import { logForDebugging } from '../utils/debug.js'
import { whichSync } from '../utils/which.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'
import type { SandboxDependencyCheck } from './linux-sandbox-utils.js'
import { linuxGetMandatoryDenyPaths } from './linux-sandbox-utils.js'
import {
  generateProxyEnvVars,
  normalizePathForSandbox,
  containsGlobChars,
  expandGlobPattern,
} from './sandbox-utils.js'

export interface WindowsSandboxParams {
  command: string
  needsNetworkRestriction: boolean
  httpProxyPort?: number
  socksProxyPort?: number
  readConfig: FsReadRestrictionConfig | undefined
  writeConfig: FsWriteRestrictionConfig | undefined
  allowGitConfig?: boolean
  ripgrepConfig?: { command: string; args?: string[] }
  mandatoryDenySearchDepth?: number
  abortSignal?: AbortSignal
}

/**
 * Config JSON files written per-invocation, cleaned up after the command exits.
 * The helper binary also deletes its config on exit, but belt-and-suspenders
 * in case the helper itself crashes before reaching its cleanup.
 */
const pendingConfigFiles = new Set<string>()

/**
 * Locate a vendored AppContainer binary (helper or forwarder).
 *
 * Mirrors the three-candidate search pattern used by generate-seccomp-filter.ts
 * for the Linux apply-seccomp binary: bundled-alongside, package-root, dist/.
 */
function findVendoredBinary(filename: string): string | null {
  const arch = process.arch === 'arm64' ? 'arm64' : 'x64'

  const baseDir = dirname(fileURLToPath(import.meta.url))
  const rel = join('vendor', 'appcontainer', arch, filename)

  const candidates = [
    join(baseDir, rel), // bundled alongside (e.g. when bundled into a consumer)
    join(baseDir, '..', '..', rel), // package root: vendor/appcontainer/...
    join(baseDir, '..', rel), // dist: dist/vendor/appcontainer/...
  ]

  for (const c of candidates) {
    if (existsSync(c)) return c
  }
  return null
}

export function getAppContainerHelperPath(): string | null {
  return findVendoredBinary('srt-appcontainer.exe')
}

export function getPipeForwarderPath(): string | null {
  return findVendoredBinary('srt-pipe-forwarder.exe')
}

export function checkWindowsDependencies(): SandboxDependencyCheck {
  const helperPath = getAppContainerHelperPath()
  if (!helperPath) {
    return {
      errors: [
        'srt-appcontainer.exe not found. Build it with: .\\scripts\\build-appcontainer-binary.ps1',
      ],
      warnings: [],
    }
  }
  return { errors: [], warnings: [] }
}

/**
 * Crash recovery: find leftover .aclstate sidecar files from prior srt runs
 * that died before cleanup, and for each one invoke the helper in --sweep mode
 * to revoke the ACLs and delete the AppContainer profile.
 *
 * Stale ACLs are harmless (the SID is per-invocation and never reused) but
 * they accumulate as clutter on allowWrite directories. Stale profiles also
 * clutter HKCU\Software\Classes\Local Settings\...\AppContainer.
 */
export function sweepStaleAppContainerState(): void {
  const helperPath = getAppContainerHelperPath()
  if (!helperPath) return

  const tmp = tmpdir()
  let entries: string[]
  try {
    entries = readdirSync(tmp)
  } catch {
    return
  }

  for (const entry of entries) {
    if (!entry.startsWith('srt-') || !entry.endsWith('.aclstate')) continue
    const sidecarPath = join(tmp, entry)
    try {
      execFileSync(helperPath, ['--sweep', sidecarPath], {
        stdio: 'ignore',
        timeout: 10000,
      })
      logForDebugging(`Swept stale AppContainer state: ${sidecarPath}`)
    } catch {
      // Best-effort. If sweep fails (e.g. the path in the sidecar was
      // deleted), just remove the sidecar — the ACL refers to a SID that
      // will never be used again, so it's inert clutter.
      try {
        rmSync(sidecarPath, { force: true })
      } catch {
        // ignore
      }
    }
  }
}

/**
 * Resolve a user-supplied path to a literal filesystem path suitable for ACL
 * operations. ACLs need real paths — no globs, no ~, resolved symlinks.
 * Glob patterns are expanded to the set of currently-matching paths.
 */
function resolvePathsForAcl(inputPaths: string[]): string[] {
  const out: string[] = []
  for (const p of inputPaths) {
    if (containsGlobChars(p)) {
      // expandGlobPattern normalizes internally
      out.push(...expandGlobPattern(p))
    } else {
      const normalized = normalizePathForSandbox(p)
      if (existsSync(normalized)) {
        out.push(normalized)
      }
    }
  }
  return out
}

/**
 * Quote a path for cmd.exe. With /s mode (which Node's {shell:true} uses on
 * Windows: cmd.exe /d /s /c "..."), the outer quotes are stripped and the
 * rest is passed through. We just need to double-quote each path and ensure
 * no internal double-quotes (which Windows paths cannot contain anyway).
 */
function cmdQuote(p: string): string {
  return `"${p}"`
}

/**
 * Resolve directories that need an RX grant for the user's binary to launch.
 *
 * The AppContainer SID has no read/execute on user-profile dirs (scoop, nvm,
 * npm-global — no ALL APPLICATION PACKAGES ACE). The helper grants RX so
 * CreateProcess can map the exe and its adjacent DLLs.
 *
 * Returns both the dir-as-found AND the realpath target. Scoop's `current`
 * is a junction; cmd.exe's PATH stat hits the junction's own DACL, but the
 * loader follows the junction and then needs RX on the TARGET. ACLs on a
 * junction don't propagate — both dirs need the grant.
 *
 * `command` is the raw user string (before cmd.exe wrapping). First
 * whitespace-delimited token, stripping quotes. Compound shell (`a && b`)
 * only resolves `a` — acceptable, the first binary is the entry point.
 */
function resolveCommandBinaryDirs(command: string): string[] {
  const m = command.match(/^\s*(?:"([^"]+)"|(\S+))/)
  if (!m) return []
  const tok = m[1] ?? m[2]

  const resolved =
    tok.includes('\\') || tok.includes('/') ? tok : whichSync(tok)
  if (!resolved || !existsSync(resolved)) return []

  // System32 already has ALL APPLICATION PACKAGES — skip to avoid ACL churn.
  if (resolved.toLowerCase().includes('\\windows\\system32\\')) return []

  const dirs = [dirname(resolved)]
  try {
    const real = realpathSync(resolved)
    const realDir = dirname(real)
    if (realDir !== dirs[0]) dirs.push(realDir)
  } catch {
    // realpath failed — still grant the as-found dir
  }
  return dirs
}

export async function wrapCommandWithSandboxWindows(
  params: WindowsSandboxParams,
): Promise<string> {
  const {
    command,
    needsNetworkRestriction,
    httpProxyPort,
    socksProxyPort,
    readConfig,
    writeConfig,
    allowGitConfig = false,
    ripgrepConfig,
    mandatoryDenySearchDepth,
    abortSignal,
  } = params

  const hasReadRestrictions = readConfig && readConfig.denyOnly.length > 0
  const hasWriteRestrictions = writeConfig !== undefined

  // Same short-circuit as macOS: if nothing to restrict, don't wrap.
  if (
    !needsNetworkRestriction &&
    !hasReadRestrictions &&
    !hasWriteRestrictions
  ) {
    return command
  }

  const helperPath = getAppContainerHelperPath()
  if (!helperPath) {
    throw new Error(
      'srt-appcontainer.exe not found in vendor/appcontainer/. ' +
        'Build it with: .\\scripts\\build-appcontainer-binary.ps1',
    )
  }

  const invocationId = randomBytes(8).toString('hex')
  const profileName = `srt-${invocationId}`
  const configPath = join(tmpdir(), `srt-${invocationId}.json`)
  const sidecarPath = join(tmpdir(), `srt-${invocationId}.aclstate`)

  // --- allowWrite -----------------------------------------------------------
  // Start with Windows-appropriate defaults, then add user-specified paths.
  // All must be resolved to literal existing paths for ACL operations.
  const claudeTmp = process.env.CLAUDE_TMPDIR || join(tmpdir(), 'claude')
  try {
    mkdirSync(claudeTmp, { recursive: true })
  } catch {
    // already exists or EACCES — either way, don't block on it
  }

  const allowWriteInput: string[] = [claudeTmp]
  if (writeConfig) {
    allowWriteInput.push(...writeConfig.allowOnly)
  }
  const allowWrite = resolvePathsForAcl(allowWriteInput)

  // --- denyRead + mandatory denies ------------------------------------------
  // The helper strips the AppContainer SID's inherited ALLOW from each
  // denyRead path and protects the DACL from re-inheritance, which blocks
  // both read and write (AppContainer access checks ignore DENY ACEs, so we
  // remove the ALLOW instead). Cleanup restores inheritance via UNPROTECTED.
  const denyReadInput: string[] = []
  if (readConfig) {
    denyReadInput.push(...readConfig.denyOnly)
  }
  if (writeConfig) {
    denyReadInput.push(...writeConfig.denyWithinAllow)
  }

  // Mandatory deny scan. The ripgrep scanner is named "linux" but is
  // platform-agnostic — it uses path.sep/path.resolve throughout.
  if (hasWriteRestrictions) {
    try {
      const found = await linuxGetMandatoryDenyPaths(
        ripgrepConfig,
        mandatoryDenySearchDepth,
        allowGitConfig,
        abortSignal,
      )
      denyReadInput.push(...found)
    } catch (e) {
      logForDebugging(
        `Windows mandatory deny scan failed: ${e instanceof Error ? e.message : String(e)}`,
      )
    }
  }

  const denyRead = resolvePathsForAcl(denyReadInput)

  // --- env ------------------------------------------------------------------
  // generateProxyEnvVars returns ["KEY=value", ...]. The helper merges these
  // on top of its inherited environment.
  //
  // When network restriction is active, the pipe bridge exposes fixed
  // in-container ports (3128 http, 1080 socks) that map to the real proxy
  // ports via the helper's pipe→TCP forwarding. The env vars must point at
  // the in-container ports, not the host proxy ports (which are unreachable
  // from inside the AppContainer).
  const bridgeActive =
    needsNetworkRestriction && (httpProxyPort || socksProxyPort)
  const env = generateProxyEnvVars(
    bridgeActive && httpProxyPort ? 3128 : httpProxyPort,
    bridgeActive && socksProxyPort ? 1080 : socksProxyPort,
  )

  // --- child command line ---------------------------------------------------
  // The helper passes `command` straight to CreateProcessW. We want cmd.exe
  // to interpret the user's command (for pipes, env var expansion, etc.) the
  // same way the macOS/Linux backends use bash -c.
  //
  // /d: skip AutoRun registry commands
  // /s: modify quote handling — with /s, cmd strips the OUTERMOST pair of
  //     quotes and preserves everything inside, which is exactly what we
  //     want for a command that may itself contain quotes.
  // /c: run and exit
  const grantExecuteDirs = resolveCommandBinaryDirs(command)
  for (const d of grantExecuteDirs) {
    logForDebugging(`Windows AppContainer: granting RX on ${d}`)
  }

  const comspec = process.env.COMSPEC || 'C:\\Windows\\System32\\cmd.exe'
  const childCmd = `${cmdQuote(comspec)} /d /s /c "${command}"`

  // --- write config + return ------------------------------------------------
  const forwarderPath = bridgeActive ? getPipeForwarderPath() : null
  if (bridgeActive && !forwarderPath) {
    throw new Error(
      'srt-pipe-forwarder.exe not found in vendor/appcontainer/. ' +
        'Build it with: .\\scripts\\build-appcontainer-binary.ps1',
    )
  }

  const helperConfig = {
    profileName,
    command: childCmd,
    sidecarPath,
    allowWrite,
    grantExecuteDirs,
    denyRead,
    env,
    needsNetworkRestriction,
    // Host-side proxy ports for the helper's pipe→TCP bridge threads.
    // Zero means that half of the bridge is disabled.
    httpProxyPort: bridgeActive ? (httpProxyPort ?? 0) : 0,
    socksProxyPort: bridgeActive ? (socksProxyPort ?? 0) : 0,
    forwarderPath: forwarderPath ? resolve(forwarderPath) : '',
  }

  writeFileSync(configPath, JSON.stringify(helperConfig), 'utf-8')
  pendingConfigFiles.add(configPath)

  logForDebugging(
    `Windows AppContainer: profile=${profileName} ` +
      `allowWrite=${allowWrite.length} denyRead=${denyRead.length} ` +
      `network=${needsNetworkRestriction}`,
  )

  // The returned string goes through spawn(..., { shell: true }) which on
  // Windows becomes: cmd.exe /d /s /c "<returned string>". Both the helper
  // path and config path may contain spaces (%TEMP% often does), so quote
  // both. No cmd.exe metacharacters (& | < > ^ %) appear in either path —
  // helper is under vendor/, config is srt-<hex>.json — so no further
  // escaping is needed.
  return `${cmdQuote(resolve(helperPath))} --config ${cmdQuote(configPath)}`
}

/**
 * Remove config JSON files written by wrapCommandWithSandboxWindows.
 * Called from SandboxManager.cleanupAfterCommand() after the child exits.
 * The helper also deletes its own config on exit; this covers helper crashes.
 */
export function cleanupWindowsConfigFiles(): void {
  for (const f of pendingConfigFiles) {
    try {
      rmSync(f, { force: true })
    } catch {
      // ignore
    }
  }
  pendingConfigFiles.clear()
}
