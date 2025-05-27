import * as core from "@actions/core";
import * as exec from "@actions/exec";
import * as github from "@actions/github";
import * as fs from "fs/promises";
import * as os from "os"; // Will be the mocked version after hoisting
import * as path from "path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MockInstance, Mocked } from "vitest";

import { run } from "../src/run";

// Define constants that might be used by tests AFTER mocks are set up.
const MOCK_TEMP_DIR = "/mock/actions_tmp"; // For use within tests
const MOCK_REPO_PATH = "/mock/repo";

// --- Hoisted Mocks ---
// Mock 'os' module: Inline the value directly in the mock factory.
vi.mock("os", async (importOriginal) => {
  const actualOs = await importOriginal<typeof os>();
  return {
    ...actualOs,
    tmpdir: vi.fn().mockReturnValue("/mock/actions_tmp"), // Inlined value
  };
});

vi.mock("@actions/exec");
vi.mock("fs/promises");
vi.mock("@actions/github", async (importOriginal) => {
  const originalModule = await importOriginal<typeof github>();
  return {
    ...originalModule,
    context: {
      eventName: "pull_request",
      sha: "test-sha-12345",
      repo: { owner: "test-owner", repo: "test-repo" },
      payload: { pull_request: { number: 123 } },
      issue: { owner: "test-owner", repo: "test-repo", number: 123 },
    },
    getOctokit: vi.fn().mockReturnValue({
      rest: {
        issues: {
          createComment: vi.fn().mockResolvedValue({ status: 201 }),
        },
      },
    }),
  };
});

// --- Typed Mocks for Convenience (after vi.mock calls) ---
const mockedExec = exec as Mocked<typeof exec>;
const mockedFs = fs as Mocked<typeof fs>;
// const mockedOs = os as Mocked<typeof os>; // os is already mocked
const mockedGithub = github as Mocked<typeof github>;

// --- Test Suite (rest of your test code) ---
describe("large-file-auditor action (run.ts)", () => {
  let infoMock: MockInstance;
  let warningMock: MockInstance;
  let getInputMock: MockInstance;
  let setFailedMock: MockInstance;
  let setOutputMock: MockInstance;
  let mathRandomSpy: MockInstance;

  const DEFAULT_MOCK_THRESHOLD = "1M";
  // MOCK_UNIQUE_ID is not used in getExpectedMirrorPath, Math.random is spied upon directly

  beforeEach(() => {
    infoMock = vi.spyOn(core, "info").mockImplementation();
    warningMock = vi.spyOn(core, "warning").mockImplementation();
    getInputMock = vi.spyOn(core, "getInput").mockImplementation();
    setOutputMock = vi.spyOn(core, "setOutput").mockImplementation();
    setFailedMock = vi.spyOn(core, "setFailed").mockImplementation();

    // Spy on Math.random for predictable unique IDs
    mathRandomSpy = vi.spyOn(Math, "random").mockReturnValue(0.123456789);

    // ** CRITICAL FIX: Re-apply mockReturnValue for os.tmpdir **
    // vi.restoreAllMocks() in afterEach resets vi.fn() instances.
    // os.tmpdir from the vi.mock factory is a vi.fn().
    (os.tmpdir as MockInstance).mockReturnValue(MOCK_TEMP_DIR);

    vi.spyOn(process, "cwd").mockReturnValue(MOCK_REPO_PATH);

    getInputMock.mockImplementation((name: string): string => {
      if (name === "file-size-threshold") return DEFAULT_MOCK_THRESHOLD;
      if (name === "github-token") return "";
      return "";
    });

    mockedExec.exec.mockResolvedValue(0); // Default for most exec calls
    mockedFs.readdir.mockResolvedValue(["blob-shas-and-paths.txt"]);
    mockedFs.readFile.mockResolvedValue(
      "===\nFormat:\n" +
        "abcdef1234567890abcdef1234567890abcdef12 100000 50000 small_file.txt\n",
    );
    mockedFs.rm.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const getExpectedMirrorPath = () => {
    const randomVal = 0.123456789; // Same as mocked Math.random
    const uniqueIdFromRandom = randomVal.toString(36).substring(2, 10);
    // Uses the MOCK_TEMP_DIR constant, which is fine here as this function is called during test execution, not during mock setup.
    return path.join(MOCK_TEMP_DIR, `mirror-repo-${uniqueIdFromRandom}.git`);
  };

  // ... (rest of your `it` test cases) ...
  // For example:
  it("should successfully run without finding large files and clean up its specific mirror repo", async () => {
    await run();

    const expectedMirrorRepoPath = getExpectedMirrorPath();

    expect(getInputMock).toHaveBeenCalledWith("file-size-threshold", {
      required: true,
    });
    expect(mockedExec.exec).toHaveBeenCalledWith(
      "git-filter-repo",
      ["--version"],
      { silent: true },
    );
    expect(mockedExec.exec).toHaveBeenCalledWith(
      "git",
      ["clone", "--mirror", ".", expectedMirrorRepoPath],
      { cwd: MOCK_REPO_PATH },
    );
    expect(mockedExec.exec).toHaveBeenCalledWith(
      "git-filter-repo",
      ["--analyze"],
      { cwd: expectedMirrorRepoPath },
    );
    expect(mockedFs.readFile).toHaveBeenCalledWith(
      path.join(
        expectedMirrorRepoPath,
        "filter-repo",
        "analysis",
        "blob-shas-and-paths.txt",
      ),
      "utf-8",
    );
    expect(setFailedMock).not.toHaveBeenCalled();
    expect(setOutputMock).toHaveBeenCalledWith("large-files-found", false);
    expect(setOutputMock).toHaveBeenCalledWith("large-files-list", "[]");
    expect(infoMock).toHaveBeenCalledWith(
      "✅ No files found exceeding the size threshold.",
    );
    expect(mockedFs.rm).toHaveBeenCalledWith(expectedMirrorRepoPath, {
      recursive: true,
      force: true,
    });
    expect(infoMock).toHaveBeenCalledWith(
      `Cleaning up ${expectedMirrorRepoPath}`,
    );
  });

  // Add other tests here as previously defined
  it("should attempt to install git-filter-repo via pip if not found in PATH", async () => {
    mockedExec.exec
      .mockImplementationOnce(async (command, args) => {
        // First call for git-filter-repo --version
        if (command === "git-filter-repo" && args?.includes("--version")) {
          throw new Error("Not found"); // Simulate not found by throwing
        }
        return 0;
      })
      .mockResolvedValue(0); // Subsequent calls succeed

    await run();

    const expectedMirrorRepoPath = getExpectedMirrorPath();

    expect(mockedExec.exec).toHaveBeenCalledWith(
      "git-filter-repo",
      ["--version"],
      { silent: true },
    );
    expect(infoMock).toHaveBeenCalledWith(
      "git-filter-repo not found in PATH, attempting to install via pip...",
    );
    expect(mockedExec.exec).toHaveBeenCalledWith("pip3", [
      "install",
      "git-filter-repo",
    ]);
    // The second call to git-filter-repo --version after install attempt
    expect(mockedExec.exec).toHaveBeenCalledWith("git-filter-repo", [
      "--version",
    ]);
    expect(infoMock).toHaveBeenCalledWith(
      "git-filter-repo installed successfully via pip.",
    );
    expect(mockedFs.rm).toHaveBeenCalledWith(expectedMirrorRepoPath, {
      recursive: true,
      force: true,
    });
  });

  it("should handle git-filter-repo --analyze failure gracefully", async () => {
    mockedExec.exec.mockImplementation(async (command, args) => {
      if (command === "git-filter-repo" && args?.includes("--analyze")) {
        throw new Error("GFRA analyze failed");
      }
      // For "git-filter-repo --version" to succeed:
      if (command === "git-filter-repo" && args?.includes("--version")) {
        return 0;
      }
      // For "git clone" to succeed:
      if (command === "git" && args?.includes("clone")) {
        return 0;
      }
      return 0;
    });

    await run();
    const expectedMirrorRepoPath = getExpectedMirrorPath();

    expect(setFailedMock).toHaveBeenCalledWith(
      expect.stringContaining(
        "git-filter-repo --analyze failed: GFRA analyze failed",
      ),
    );
    expect(mockedFs.rm).toHaveBeenCalledWith(expectedMirrorRepoPath, {
      recursive: true,
      force: true,
    });
  });

  it("should warn if blob-shas-and-paths.txt is not found", async () => {
    mockedFs.readdir.mockResolvedValue(["other-file.txt"]);

    await run();
    const expectedMirrorRepoPath = getExpectedMirrorPath();

    expect(warningMock).toHaveBeenCalledWith(
      expect.stringContaining(
        'No "blob-shas-and-paths.txt" analysis file found.',
      ),
    );
    expect(setOutputMock).toHaveBeenCalledWith("large-files-found", false);
    expect(setOutputMock).toHaveBeenCalledWith("large-files-list", "[]");
    expect(infoMock).toHaveBeenCalledWith(
      "✅ No large files to report based on analysis files.",
    );
    expect(setFailedMock).not.toHaveBeenCalled();
    expect(mockedFs.rm).toHaveBeenCalledWith(expectedMirrorRepoPath, {
      recursive: true,
      force: true,
    });
  });

  it("should correctly parse file size threshold with various units", async () => {
    getInputMock.mockImplementation((name: string): string => {
      if (name === "file-size-threshold") return "2K";
      return "";
    });
    await run(); // First run with 2K
    expect(infoMock).toHaveBeenCalledWith("Threshold in bytes: 2048");

    // Clear infoMock calls or check for the last relevant call if it's not reset per run
    infoMock.mockClear(); // Reset for the next assertion on the same mock

    getInputMock.mockImplementation((name: string): string => {
      if (name === "file-size-threshold") return "3G";
      return "";
    });
    await run(); // Second run with 3G
    expect(infoMock).toHaveBeenCalledWith(
      `Threshold in bytes: ${3 * 1024 * 1024 * 1024}`,
    );
  });

  it("should fail if file size threshold format is invalid", async () => {
    getInputMock.mockImplementation((name: string): string => {
      if (name === "file-size-threshold") return "1X";
      return "";
    });
    await run();
    expect(setFailedMock).toHaveBeenCalledWith(
      "Invalid file size threshold format: 1X",
    );
    expect(mockedFs.rm).not.toHaveBeenCalled();
  });

  it("should clean up even if an error occurs mid-process before analysis", async () => {
    mockedExec.exec.mockImplementation(async (command, args) => {
      if (command === "git" && args?.includes("clone")) {
        return 0;
      }
      if (command === "git-filter-repo" && args?.includes("--version")) {
        // For initial check and potential re-check
        return 0;
      }
      // Make a specific command fail after clone, but before real analysis actions
      // For example, let's assume the 'git-filter-repo --analyze' call is what we want to fail
      if (command === "git-filter-repo" && args?.includes("--analyze")) {
        throw new Error("Pre-analysis error for git-filter-repo --analyze");
      }
      return 0; // Other exec calls succeed
    });

    await run();
    const expectedMirrorRepoPath = getExpectedMirrorPath();

    expect(setFailedMock).toHaveBeenCalledWith(
      expect.stringContaining(
        "git-filter-repo --analyze failed: Pre-analysis error for git-filter-repo --analyze",
      ),
    );
    expect(infoMock).toHaveBeenCalledWith(
      `Cleaning up ${expectedMirrorRepoPath}`,
    );
    expect(mockedFs.rm).toHaveBeenCalledWith(expectedMirrorRepoPath, {
      recursive: true,
      force: true,
    });
  });
});
