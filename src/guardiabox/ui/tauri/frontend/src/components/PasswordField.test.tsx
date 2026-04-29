import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import "@/i18n";
import { PasswordField } from "./PasswordField";

describe("PasswordField", () => {
  it("renders with placeholder + masked input", () => {
    render(<PasswordField value="" onChange={vi.fn()} placeholder="Mot de passe" />);
    const input = screen.getByPlaceholderText(/mot de passe/i) as HTMLInputElement;
    expect(input.type).toBe("password");
  });

  it("calls onChange on each keystroke", () => {
    const onChange = vi.fn();
    render(<PasswordField value="" onChange={onChange} placeholder="x" />);
    fireEvent.change(screen.getByPlaceholderText("x"), { target: { value: "abc" } });
    expect(onChange).toHaveBeenCalledWith("abc");
  });

  it("shows the strength label live", () => {
    render(<PasswordField value="Aa1!Aa1!Aa1!Aa1!Aa1!" onChange={vi.fn()} />);
    // 'Excellent' on score 4. Label is visible via aria-live.
    expect(screen.getByRole("status")).toBeInTheDocument();
  });

  it("hides the strength bar when showStrength is false", () => {
    render(<PasswordField value="abc" onChange={vi.fn()} showStrength={false} />);
    expect(screen.queryByRole("status")).toBeNull();
  });
});
