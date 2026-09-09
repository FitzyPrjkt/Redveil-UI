// See findings/[wpoc_id]/layout.tsx for why we use a placeholder.
export function generateStaticParams() {
  return [{ id: "_" }];
}
export default function SegmentLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
