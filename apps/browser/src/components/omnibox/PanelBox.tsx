import { useState, type ComponentProps, type ReactNode } from "react";
import { View } from "react-native";
import { Surface } from "../ui";
import { noteCommandBarOpenRelayout } from "../../state/telemetry/inlineCompletionCounts";

export const OPEN_SETTLE_MS = 250;

export function PanelBox({
  frame,
  surface,
  clipRadius,
  children,
}: {
  frame: { left: number; top: number; width: number };
  clipRadius?: number;
  surface: Omit<ComponentProps<typeof Surface>, "style">;
  children: ReactNode;
}) {
  const [watch] = useState(openRelayoutWatch);
  return (
    <View testID="ardia-command-panel" onLayout={(e) => watch(e.nativeEvent.layout)} style={{ position: "absolute", ...frame }}>
      <Surface {...surface} style={{ position: "absolute", top: 0, left: 0, right: 0, bottom: 0 }} />
      {clipRadius === undefined ? children : <View style={{ overflow: "hidden", borderRadius: clipRadius }}>{children}</View>}
    </View>
  );
}

export function openRelayoutWatch(now: () => number = Date.now) {
  const openedAt = now();
  let first: { width: number; height: number } | null = null;
  let counted = false;
  return ({ width, height }: { width: number; height: number }) => {
    if (counted || now() - openedAt > OPEN_SETTLE_MS) return;
    if (!first) return void (first = { width, height });
    if (width === first.width && height >= first.height) return void (first = { width, height });
    counted = true;
    noteCommandBarOpenRelayout();
  };
}
