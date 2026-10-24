module example.com/timeconf-consumer

go 1.25

require github.com/relux-works/swarma-credential-broker v0.0.0

require golang.org/x/sys v0.38.0 // indirect

replace github.com/relux-works/swarma-credential-broker => ../..
