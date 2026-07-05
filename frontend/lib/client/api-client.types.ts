export class ApiClientError extends Error {
  status: number
  body: unknown

  constructor(status: number, body: unknown, message?: string) {
    super(message ?? `HTTP ${status}`)
    this.name = "ApiClientError"
    this.status = status
    this.body = body
  }
}

export class CsrfMissingError extends Error {
  constructor() {
    super("CSRF cookie not found — user is not authenticated")
    this.name = "CsrfMissingError"
  }
}
