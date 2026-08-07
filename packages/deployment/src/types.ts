/** A digest-pinned OCI image reference. Tags are intentionally rejected. */
export interface ImageReference {
  readonly repository: string;
  readonly digest: `sha256:${string}`;
}

export interface ResourceLimits {
  readonly memoryBytes: number;
  readonly cpuCores: number;
  readonly pids: number;
  readonly tmpfsBytes: number;
  readonly maxBodyBytes: number;
  readonly maxVaultBytes: number;
  readonly maxDatabaseBytes: number;
  readonly maxIndexBytes: number;
  readonly maxTempBytes: number;
  readonly minFreeBytes: number;
  readonly maxRetainedGenerations: number;
  readonly logBytes: number;
  readonly logFiles: number;
}

export interface SecretReference {
  /** Docker Compose secret key. This is not a secret value. */
  readonly name: string;
  /** A file below the installation directory, owned by the deployment user. */
  readonly file: string;
  readonly uid: number;
  readonly gid: number;
  readonly mode?: number;
}

export interface RuntimeImages {
  readonly server: ImageReference;
  readonly tunnel: ImageReference;
}

export interface RuntimeEndpoints {
  readonly mcpHost: string;
  readonly publisherHost: string;
}

export interface RuntimeEnvironment {
  readonly nodeEnvironment?: "production";
  readonly serverPort?: number;
  readonly databasePath?: string;
  readonly mcpResourceUrl: string;
  readonly publisherUrl: string;
  readonly jwtIssuer: string;
  readonly jwtAudience: string;
  readonly jwtScope?: string;
  readonly jwtClientId?: string;
  readonly jwksFile?: string;
  readonly allowedHosts: string;
  readonly limits?: Readonly<Record<string, string | number>>;
}

export interface DeploymentSpec {
  readonly installationId: string;
  readonly vaultId: string;
  readonly installationDirectory: string;
  readonly images: RuntimeImages;
  readonly endpoints: RuntimeEndpoints;
  readonly environment: RuntimeEnvironment;
  readonly tunnelCredential: SecretReference;
  /** Edge attestation secret; never the Mac publisher mTLS private key. */
  readonly publisherEdgeAttestationSecret: SecretReference;
  /** Admission attestation for MCP traffic; distinct from publisher ingest. */
  readonly mcpEdgeAttestationSecret: SecretReference;
  readonly oauthVerificationBundle: SecretReference;
  readonly limits: ResourceLimits;
  readonly deploymentUid?: number;
  readonly deploymentGid?: number;
  readonly runtimeMode?: "rootless" | "rootful";
}

export interface ComposeProject {
  readonly installationId: string;
  readonly projectName: string;
  readonly fileName: string;
  readonly yaml: string;
  readonly dataVolumeName: string;
  readonly labels: Readonly<Record<string, string>>;
}

export interface CommandResult {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
}

export interface CommandRunner {
  run(command: string, args: readonly string[], options?: {
    readonly cwd?: string;
    readonly env?: Readonly<Record<string, string | undefined>>;
    readonly timeoutMs?: number;
    readonly signal?: AbortSignal;
  }): Promise<CommandResult>;
}

export interface DockerProbe {
  readonly available: boolean;
  readonly version?: string;
  readonly rootless: boolean;
  readonly composeAvailable: boolean;
  readonly composeVersion?: string;
  readonly context?: string;
}

export interface HostProbe {
  readonly os: string;
  readonly arch: string;
  readonly docker: DockerProbe;
  readonly cpuCores: number;
  readonly memoryBytes: number;
  readonly freeSpaceBytes: number;
  readonly outboundHttps: boolean;
  readonly projectNames: readonly string[];
  readonly filesystemQuota: "available" | "unavailable" | "unknown";
}

export interface PreflightRequirements {
  readonly mode: "rootless" | "rootful";
  readonly allowedArchitectures?: readonly string[];
  readonly minimumCpuCores?: number;
  readonly minimumMemoryBytes?: number;
  readonly minimumFreeSpaceBytes?: number;
  readonly requireOutboundHttps?: boolean;
  readonly expectedStagingBytes?: number;
}

export interface PreflightCheck {
  readonly id: string;
  readonly status: "pass" | "warn" | "fail";
  readonly detail: string;
}

export interface PreflightReport {
  readonly ok: boolean;
  readonly checks: readonly PreflightCheck[];
  readonly collision: boolean;
}

export interface LifecycleResult {
  readonly operation: ComposeOperation;
  readonly command: readonly string[];
  readonly result: CommandResult;
}

export type ComposeOperation =
  | "config"
  | "pull"
  | "start"
  | "stop"
  | "status"
  | "logs"
  | "rollback";

export interface LifecycleOptions {
  readonly project: ComposeProject;
  readonly composeFile: string;
  readonly runner: CommandRunner;
  readonly timeoutMs?: number;
}
