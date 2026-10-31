"use client";

import { Toaster } from "sonner";
import { SWRConfig } from "swr";

import { InvestigationProvider } from "@/components/soc/investigation-context";
import { TooltipProvider } from "@/components/ui/primitives";
import { fetcher } from "@/lib/api";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <SWRConfig value={{ fetcher, revalidateOnFocus: false, shouldRetryOnError: false }}>
      <TooltipProvider>
        <InvestigationProvider>{children}</InvestigationProvider>
        <Toaster
          theme="system"
          position="bottom-right"
          toastOptions={{ className: "!bg-elevated !border-border-strong !text-foreground !text-[13px]" }}
        />
      </TooltipProvider>
    </SWRConfig>
  );
}
