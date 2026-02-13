# Minimal Rails config.ru stub for framework detection
run lambda { |env| [200, { "Content-Type" => "text/plain" }, ["Hello from Rails"]] }
