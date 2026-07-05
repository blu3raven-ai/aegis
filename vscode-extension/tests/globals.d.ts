// Augment globalThis to allow the vscode mock guard flag used across test files.
declare global {
  // eslint-disable-next-line no-var
  var __aegisVscodeMockInstalled: boolean | undefined
}
export {}
