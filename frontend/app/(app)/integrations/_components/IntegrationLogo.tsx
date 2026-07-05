"use client";
import { useEffect, useState, type CSSProperties } from "react";
import { Mail, Server, Webhook } from "lucide-react";
import { cn } from "@/lib/shared/utils";

const GENERIC_ICONS: Partial<Record<string, React.ComponentType<{ className?: string }>>> = {
  email: Mail,
  webhook: Webhook,
  runner: Server,
};

function initialsFromName(name: string): string {
  const words = name.split(/\s+/).filter(Boolean);
  if (words.length === 0) return "";
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[1][0]).toUpperCase();
}

interface BrandMarkProps {
  iconSlug: string;
  name: string;
  /** Size class for the rendered mark (defaults to `h-5 w-5`). */
  className?: string;
}

/** Just the brand mark — no surrounding container. Renders monochrome in `currentColor`. */
export function IntegrationLogoMark({ iconSlug, name, className }: BrandMarkProps) {
  const Generic = GENERIC_ICONS[iconSlug];
  const [errored, setErrored] = useState(false);

  useEffect(() => {
    if (Generic || errored) return;
    const img = new window.Image();
    img.onerror = () => setErrored(true);
    img.src = `https://cdn.simpleicons.org/${iconSlug}`;
  }, [iconSlug, Generic, errored]);

  if (Generic) return <Generic className={cn("h-5 w-5", className)} />;

  if (errored) {
    return (
      <span
        role="img"
        aria-label={`${name} logo`}
        className={cn(
          "inline-flex items-center justify-center text-2xs font-semibold tracking-wide",
          className,
        )}
      >
        {initialsFromName(name)}
      </span>
    );
  }

  const maskStyle: CSSProperties = {
    maskImage: `url(https://cdn.simpleicons.org/${iconSlug})`,
    maskSize: "contain",
    maskRepeat: "no-repeat",
    maskPosition: "center",
    WebkitMaskImage: `url(https://cdn.simpleicons.org/${iconSlug})`,
    WebkitMaskSize: "contain",
    WebkitMaskRepeat: "no-repeat",
    WebkitMaskPosition: "center",
  };

  return (
    <span
      role="img"
      aria-label={`${name} logo`}
      className={cn("inline-block bg-current", className ?? "h-5 w-5")}
      style={maskStyle}
    />
  );
}
