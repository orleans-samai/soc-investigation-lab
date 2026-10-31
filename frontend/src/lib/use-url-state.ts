"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import * as React from "react";

/** Filter state mirrored in the query string, so filtered views can be bookmarked and shared. */
export function useUrlState<T extends Record<string, string>>(defaults: T): [T, (patch: Partial<T>) => void, () => void] {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();

  const state = React.useMemo(() => {
    const out = { ...defaults };
    for (const key of Object.keys(defaults) as (keyof T)[]) {
      const v = params.get(key as string);
      if (v !== null) out[key] = v as T[keyof T];
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);

  const update = React.useCallback(
    (patch: Partial<T>) => {
      const next = new URLSearchParams(params.toString());
      for (const [k, v] of Object.entries(patch)) {
        if (v === undefined || v === "" || v === defaults[k]) next.delete(k);
        else next.set(k, String(v));
      }
      if (!("page" in patch) && "page" in defaults) next.delete("page");
      const text = next.toString();
      router.replace(text ? `${pathname}?${text}` : pathname, { scroll: false });
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [params, pathname, router],
  );

  const reset = React.useCallback(() => router.replace(pathname, { scroll: false }), [pathname, router]);
  return [state, update, reset];
}
