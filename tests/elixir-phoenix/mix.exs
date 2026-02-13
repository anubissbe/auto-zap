defmodule TestApp.MixProject do
  use Mix.Project

  def project do
    [app: :test_app, version: "0.1.0", elixir: "~> 1.17", deps: deps()]
  end

  defp deps do
    [{:phoenix, "~> 1.7"}, {:phoenix_html, "~> 4.0"}]
  end
end
