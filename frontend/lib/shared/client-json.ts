export async function readJsonResponse<T>(response: Response): Promise<T> {
  const text = await response.text()
  if (!text.trim()) return {} as T

  try {
    return JSON.parse(text) as T
  } catch {
    return {
      error: response.ok
        ? "Server returned an unreadable response."
        : `Request failed (${response.status}). Check the server logs for details.`,
    } as T
  }
}
