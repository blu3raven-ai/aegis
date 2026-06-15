import { SaveBarProvider } from "./save-bar/SaveBarProvider"
import { GlobalSaveBar } from "./save-bar/GlobalSaveBar"

export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  return (
    <SaveBarProvider>
      {children}
      <GlobalSaveBar />
    </SaveBarProvider>
  )
}
