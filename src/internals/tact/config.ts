import { Config, Project, parseConfig } from "../../internals/tact/imports";
import { VirtualFileSystem } from "../../vfs/virtualFileSystem";
import { ExecutionException, throwZodError } from "../exceptions";
import { ProjectName } from "../ir";
import fs from "fs";
import path from "path";

/**
 * Manages the logic around the Tact configuration file.
 *
 * Tact config describes the structure of the project, and includes the entry
 * points to run compilation and analysis on.
 */
export class TactConfigManager {
  private constructor(
    /**
     * An absolute path to the root directory storing the configuration file.
     *
     * If the config is generated for the Tact contract, it should be a directory containing all the imported files.
     */
    private projectRoot: string,
    /** Tact config parsed with Zod. */
    private config: Config,
  ) {}

  /**
   * Creates a TactConfigManager from a Tact configuration file typically specified by the user.
   *
   * @param ctx Misti context.
   * @param tactConfigPath Path to the Tact configuration file.
   */
  public static fromConfig(tactConfigPath: string): TactConfigManager {
    return new TactConfigManager(
      path.resolve(path.dirname(tactConfigPath)),
      this.readConfig(tactConfigPath),
    );
  }

  /**
   * Creates a TactConfigManager from a single Tact contract.
   *
   * @param ctx Misti context.
   * @param projectName Name of the project.
   * @param contractPath Path to the Tact contract.
   * @param vfs Virtual file system to manage interactions with the project files.
   */
  public static fromContract(
    projectRoot: string,
    contractPath: string,
    projectName: ProjectName = path.basename(
      contractPath,
      ".tact",
    ) as ProjectName,
    vfs: VirtualFileSystem,
  ): TactConfigManager {
    let vfsContractPath: string = "";
    if (vfs.type === "local") {
      vfsContractPath = path.relative(projectRoot, contractPath);
    } else {
      const absoluteProjectRoot = vfs.resolve(projectRoot);
      const absoluteContractPath = path.resolve(projectRoot, contractPath);
      vfsContractPath = path.relative(
        absoluteProjectRoot,
        absoluteContractPath,
      );
    }
    const tactConfig: Config = {
      projects: [
        {
          name: projectName,
          path: vfsContractPath,
          output: "/tmp/misti/output", // never used
          options: {
            debug: false,
            external: true,
          },
        },
      ],
    };
    return new TactConfigManager(path.resolve(projectRoot), tactConfig);
  }

  public getConfig(): Config {
    return this.config;
  }

  /**
   * Returns absolute path to the project root.
   */
  public getProjectRoot(): string {
    return this.projectRoot;
  }

  /**
   * Gets projects defined within the configuration file.
   */
  public getProjects(): readonly Project[] {
    return this.config.projects;
  }

  /**
   * Find the project config based on the provided name.
   */
  public findProjectByName(projectName: ProjectName): Project | undefined {
    return this.config.projects.find((project) => projectName === project.name);
  }

  /**
   * Find the project config based on the provided path.
   */
  public findProjectByPath(projectPath: string): Project | undefined {
    return this.config.projects.find(
      (project) => projectPath === this.resolveProjectPath(project.path),
    );
  }

  /**
   * Returns an absolute path or the project based on the project path.
   */
  public resolveProjectPath(projectPath: string): string {
    return path.resolve(this.projectRoot, projectPath);
  }

  /**
   * Reads the Tact configuration file from the specified path, parses it, and returns
   * the Config object.
   * @throws If the config file does not exist or cannot be parsed.
   * @returns The parsed Config object.
   */
  private static readConfig(tactConfigPath: string): Config {
    const resolvedPath = path.resolve(tactConfigPath);
    if (!fs.existsSync(resolvedPath)) {
      throw ExecutionException.make(
        `Unable to find config file at ${resolvedPath}`,
      );
    }
    try {
      return parseConfig(fs.readFileSync(resolvedPath, "utf8"));
    } catch (err) {
      throwZodError(err, {
        msg: `Incorrect Tact Project file ${resolvedPath}:`,
        help: [
          `Ensure ${resolvedPath} is a Tact Project file.`,
          "See https://docs.tact-lang.org/book/config/ for additional information.",
        ].join(" "),
      });
    }
  }

  /**
   * Returns absolute paths to entry points specified in the Tact configuration file.
   */
  public getEntryPoints(): string[] {
    return this.config.projects.map((p) => this.resolveProjectPath(p.path));
  }
}
