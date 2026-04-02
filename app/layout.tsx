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

const DEFAULT_TITLE = "Blu3Raven | Aegis - Vulnerability Management Portal"
const DEFAULT_ICON = "/logo-brand.png"

export const metadata: Metadata = {
  title: DEFAULT_TITLE,
  description: "Central portal for vulnerability management across your application security workflows.",
  icons: {
    icon: DEFAULT_ICON,
  },
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
      <body className="bg-[var(--color-bg)] text-[var(--color-text-primary)] antialiased min-h-screen relative">
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
