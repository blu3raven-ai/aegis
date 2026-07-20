"use client";
import { Sheet } from "@/components/ui/Sheet";
import type { Integration } from "@/lib/client/integrations-catalog-api";
import { IntegrationSetup } from "./IntegrationSetup";

interface IntegrationDrawerProps {
  integration: Integration | null;
  onClose: () => void;
}

export function IntegrationDrawer({ integration, onClose }: IntegrationDrawerProps) {
  return (
    <Sheet
      open={integration !== null}
      onClose={onClose}
      title={integration?.name ?? ""}
      variant="modal"
      description={integration?.description}
      size="xl"
    >
      {integration && <IntegrationSetup integration={integration} />}
    </Sheet>
  );
}
