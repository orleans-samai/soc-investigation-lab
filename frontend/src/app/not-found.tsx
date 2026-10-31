"use client";

import { Compass } from "lucide-react";
import Link from "next/link";

import { EmptyState } from "@/components/soc/common";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <EmptyState
      icon={Compass}
      title="Page not found"
      description="The page or record you are looking for does not exist in this lab."
      action={
        <Button asChild variant="primary">
          <Link href="/">Back to dashboard</Link>
        </Button>
      }
      className="py-24"
    />
  );
}
