import * as core from "@actions/core";
import * as exec from "@actions/exec";
// import * as tc from '@actions/tool-cache';
import * as github from "@actions/github";
import * as path from "path";
import * as fs from "fs/promises"; // Use promises for async file operations
import * as os from "os";

interface LargeFileDetail {
  path?: string; // May not always be unique or available directly for all historical blobs
  blobSha: string;
  sizeBytes: number;
  sizeHuman: string;
}

export async function run(): Promise<void> {
  try {
    // 1. Get Inputs
    const fileSizeThresholdInput: string = core.getInput(
      "file-size-threshold",
      { required: true },
    );
    const githubToken: string | undefined = core.getInput("github-token");
    // TODO(rg): Lets handle the version check later..
    // const gfrVersionInput: string = core.getInput('git-filter-repo-version') || 'latest';

    core.info(`File size threshold: ${fileSizeThresholdInput}`);
    const thresholdBytes = parseSizeToBytes(fileSizeThresholdInput);
    if (thresholdBytes === null) {
      core.setFailed(
        `Invalid file size threshold format: ${fileSizeThresholdInput}`,
      );
      return;
    }
    core.info(`Threshold in bytes: ${thresholdBytes}`);

    // 2. Install git-filter-repo (using pip)
    // Runners usually have Python 3. Ensure pip is available.
    core.info("Ensuring git-filter-repo is installed...");
    try {
      // First, check if it's already available and works
      await exec.exec("git-filter-repo", ["--version"], { silent: true });
      core.info("git-filter-repo found in PATH.");
    } catch (e) {
      core.info(
        "git-filter-repo not found in PATH, attempting to install via pip...",
      );
      // On GitHub runners, python3-pip should be available.
      // The user of the action can use actions/setup-python if a specific python/pip is needed.
      await exec.exec("pip3", ["install", "git-filter-repo"]); // or 'pip'
      // Verify installation
      await exec.exec("git-filter-repo", ["--version"]);
      core.info("git-filter-repo installed successfully via pip.");
    }

    // 3. Prepare for analysis - Create a mirror clone
    const originalRepoPath = process.cwd();
    const uniqueId = Math.random().toString(36).substring(2, 10); // Create a unique name for the mirror
    const mirrorRepoDir = `mirror-repo-${uniqueId}.git`;
    const mirrorRepoPath = path.join(os.tmpdir(), mirrorRepoDir); // Use temp directory for mirror

    core.info(`Creating mirror clone at ${mirrorRepoPath}`);
    await exec.exec("git", ["clone", "--mirror", ".", mirrorRepoPath], {
      cwd: originalRepoPath,
    });

    // 4. Run git-filter-repo --analyze
    core.info("Running git-filter-repo --analyze...");
    const analysisPath = path.join(mirrorRepoPath, "filter-repo", "analysis");
    try {
      // Ensure the base 'filter-repo' directory for analysis doesn't exist from a prior failed run in the same temp dir
      // This is less likely with unique mirror paths but good for robustness.
      // await fs.rm(path.join(mirrorRepoPath, 'filter-repo'), { recursive: true, force: true });

      await exec.exec("git-filter-repo", ["--analyze"], {
        cwd: mirrorRepoPath,
      });
    } catch (error: any) {
      core.setFailed(
        `git-filter-repo --analyze failed: ${error.message}. Ensure the repository is not empty or corrupted.`,
      );
      return;
    }

    // 5. Parse Analysis Report
    core.info(`Looking for analysis reports in ${analysisPath}`);
    let reportFiles: string[];
    try {
      reportFiles = await fs.readdir(analysisPath);
    } catch (error: any) {
      core.setFailed(
        `Failed to read analysis directory ${analysisPath}: ${error.message}`,
      );
      return;
    }

    const targetReportFile = reportFiles.find(
      (f) => f === "blob-shas-and-paths.txt",
    );

    if (!targetReportFile) {
      core.warning(
        'No "blob-shas-and-paths.txt" analysis file found. This might happen on very small or empty repositories, or if git-filter-repo version changed output.',
      );
      core.setOutput("large-files-found", false);
      core.setOutput("large-files-list", "[]");
      core.info("✅ No large files to report based on analysis files.");
      return;
    }

    core.info(`Parsing analysis file: ${targetReportFile}`);
    const detectedLargeFiles: LargeFileDetail[] = [];
    const reportContent = await fs.readFile(
      path.join(analysisPath, targetReportFile),
      "utf-8",
    );
    const lines = reportContent.split("\n");

    // Skip header lines (first 2 lines in the example)
    // Format: sha, unpacked size, packed size, filename(s) object stored as
    // e4ecf688de51dafeee6a954ae05cdf208f34cdab   1607286     391766 dist/index.js.map
    const dataLineRegex = /^\s*([0-9a-f]{40})\s+([0-9]+)\s+([0-9]+)\s+(.*)$/;

    for (const line of lines) {
      if (
        line.startsWith("===") ||
        line.startsWith("Format:") ||
        line.trim() === ""
      ) {
        continue; // Skip headers and empty lines
      }

      const match = line.match(dataLineRegex);
      if (match) {
        const blobSha = match[1];
        const unpackedSizeBytes = parseInt(match[2], 10);
        // match[3] is packed size, we ignore it
        const filePath = match[4].trim(); // The rest of the line is the path

        if (unpackedSizeBytes >= thresholdBytes) {
          detectedLargeFiles.push({
            path: filePath, // Path is now directly available
            blobSha: blobSha,
            sizeBytes: unpackedSizeBytes,
            sizeHuman: formatBytes(unpackedSizeBytes), // Your existing helper
          });
        }
      }
    }

    // 6. Set Outputs & Action Status
    core.setOutput("large-files-found", detectedLargeFiles.length > 0);
    core.setOutput("large-files-list", JSON.stringify(detectedLargeFiles));

    if (detectedLargeFiles.length > 0) {
      let errorMessage = `🚨 Large files detected (threshold: ${fileSizeThresholdInput}):\n`;
      detectedLargeFiles.forEach((file) => {
        errorMessage += `- Blob SHA: ${file.blobSha}\n`;
        if (file.path) {
          errorMessage += `  Path hint: ${file.path}\n`;
        }
        errorMessage += `  Size: ${file.sizeHuman}\n`;
      });
      errorMessage += `\nPlease remove these files from the commit history using git filter-repo locally, then force-push the cleaned branch.`;
      errorMessage += `\nConsult the git-filter-repo documentation: https://github.com/newren/git-filter-repo`;

      core.setFailed(errorMessage);

      if (
        githubToken &&
        github.context.issue &&
        github.context.payload.pull_request
      ) {
        const octokit = github.getOctokit(githubToken);
        try {
          await octokit.rest.issues.createComment({
            owner: github.context.repo.owner,
            repo: github.context.repo.repo,
            issue_number: github.context.issue.number,
            body: errorMessage,
          });
        } catch (commentError: any) {
          core.warning(`Failed to create PR comment: ${commentError.message}`);
        }
      }
    } else {
      core.info("✅ No files found exceeding the size threshold.");
    }
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed(String(error));
    }
  } finally {
    // 7. Clean up mirror repo
    const mirrorRepoDirPrefix = `mirror-repo-`;
    const tempDir = os.tmpdir();
    try {
      const items = await fs.readdir(tempDir);
      for (const item of items) {
        if (item.startsWith(mirrorRepoDirPrefix)) {
          const itemPath = path.join(tempDir, item);
          core.info(`Cleaning up ${itemPath}`);
          await fs.rm(itemPath, { recursive: true, force: true });
        }
      }
    } catch (cleanupError: any) {
      core.warning(
        `Failed to cleanup mirror repositories: ${cleanupError.message}`,
      );
    }
  }
}

// Helper functions (parseSizeToBytes, formatBytes - same as before)
function parseSizeToBytes(sizeStr: string): number | null {
  const sizeRegex = /^(\d+)([KMGTP]?)$/i;
  const match = sizeStr.match(sizeRegex);
  if (!match) return null;

  const value = parseInt(match[1], 10);
  const unit = match[2].toUpperCase();

  switch (unit) {
    case "K":
      return value * 1024;
    case "M":
      return value * 1024 * 1024;
    case "G":
      return value * 1024 * 1024 * 1024;
    case "T":
      return value * 1024 * 1024 * 1024 * 1024;
    case "P":
      return value * 1024 * 1024 * 1024 * 1024 * 1024;
    default:
      return value; // Bytes
  }
}

function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB", "PB"]; // Simplified for practical file sizes
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  if (i >= sizes.length)
    return `${(bytes / Math.pow(k, sizes.length - 1)).toFixed(dm)} ${sizes[sizes.length - 1]}`;
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

run();
