import type { Metadata } from "next"
import { Inter, JetBrains_Mono, Space_Grotesk, Manrope } from "next/font/google"
import Script from "next/script"
import "./globals.css"
import { ThemeProvider } from "@/components/ThemeProvider"

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
})

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains-mono",
})

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-space-grotesk",
})

const manrope = Manrope({
  subsets: ["latin"],
  variable: "--font-manrope",
})

const DEFAULT_ICON = "/logo-brand.png"
const VENDOR_DEFAULT_TITLE = "Blu3Raven | Aegis - Vulnerability Management Portal"

async function getDefaultTitle(): Promise<string> {
  try {
    const base = process.env.INTERNAL_API_URL ?? "http://localhost:8000"
    const res = await fetch(`${base}/api/v1/settings/organisations/branding`, {
      cache: "no-store",
    })
    if (!res.ok) throw new Error("branding fetch failed")
    const body = (await res.json()) as { name: string | null }
    // NULL is the only vendor sentinel; any non-NULL name renders as-is.
    return body.name ?? VENDOR_DEFAULT_TITLE
  } catch {
    return VENDOR_DEFAULT_TITLE
  }
}

export async function generateMetadata(): Promise<Metadata> {
  const title = await getDefaultTitle()
  return {
    title,
    description: "Central portal for vulnerability management across your application security workflows.",
    icons: {
      icon: DEFAULT_ICON,
    },
  }
}

const THEME_SCRIPT = `try{
  var t=localStorage.getItem('theme')||'system';
  var pq=window.matchMedia('(prefers-color-scheme: dark)').matches;
  var dk=t==='dark'||(t!=='light'&&pq);
  if(dk)document.documentElement.classList.add('dark');
  else document.documentElement.classList.remove('dark');
}catch(_){}`

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${inter.variable} ${jetbrainsMono.variable} ${spaceGrotesk.variable} ${manrope.variable}`}
    >
      <body className="bg-[var(--color-bg)] text-[var(--color-text-primary)] antialiased h-screen overflow-hidden relative">
        <Script
          id="theme-bootstrap"
          strategy="beforeInteractive"
          dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }}
        />
        <ThemeProvider />
        {children}
      </body>
    </html>
  )
}
