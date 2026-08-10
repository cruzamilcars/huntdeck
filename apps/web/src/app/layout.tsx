import type { Metadata } from "next";

import "@/styles/globals.css";

export const metadata: Metadata = {
  title: "OSINT MCP Hub",
  description: "Cloud-native IOC investigation hub with MCP orchestration.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

