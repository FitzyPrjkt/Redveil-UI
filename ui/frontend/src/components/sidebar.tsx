"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  IconLayoutDashboard,
  IconTarget,
  IconHistory,
  IconPuzzle,
  IconShieldCheck,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";

interface NavItem {
  label: string;
  href: string;
  icon: React.ComponentType<{ className?: string; size?: number | string }>;
}

const navItems: NavItem[] = [
  { label: "Dashboard", href: "/", icon: IconLayoutDashboard },
  { label: "Targets", href: "/targets", icon: IconTarget },
  { label: "Scan History", href: "/scans", icon: IconHistory },
  { label: "Plugins", href: "/plugins", icon: IconPuzzle },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed inset-y-0 left-0 z-40 hidden w-60 flex-col border-r border-zinc-800 bg-zinc-950 md:flex">
      {/* Wordmark */}
      <div className="flex h-14 items-center gap-2 border-b border-zinc-800 px-4">
        <IconShieldCheck className="h-5 w-5 text-red-500" size={18} />
        <span className="font-mono text-sm font-semibold tracking-tight text-zinc-100">
          redveil
        </span>
        <span className="ml-auto font-mono text-xs text-zinc-500">1.9.5</span>
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-1 px-2 py-4">
        {navItems.map((item) => {
          const active =
            item.href === "/"
              ? pathname === "/"
              : pathname?.startsWith(item.href);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                active
                  ? "bg-zinc-800 text-zinc-100"
                  : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200",
              )}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      {/* Bottom status placeholder (Wave 5) */}
      <div className="border-t border-zinc-800 px-4 py-3 text-xs text-zinc-500">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-emerald-500" />
          <span>Lab status</span>
        </div>
      </div>
    </aside>
  );
}