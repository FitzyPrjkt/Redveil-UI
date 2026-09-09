// Dynamic segments are handled by the Python backend's SPA catch-all
// (redveil_ui/server.py) which serves the placeholder HTML built for
// this segment. The client router then re-resolves against the actual URL.
// The placeholder is what makes `output: "export"` happy — without at
// least one generateStaticParams entry, Next refuses to build.
export function generateStaticParams() {
  return [{ wpoc_id: "_" }];
}
export default function SegmentLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
