package main
import("fmt";"os";"strings";"regexp")
// Transcribed from internal/xraycfg/edit.go:306-315, c0f382f2.
func normalizeXHTTPPath(p string) string {
 p = strings.TrimSpace(p)
 if p == "" { return p }
 if !strings.HasPrefix(p, "/") { return "/" + p }
 return p
}
// Exact regex from internal/deploy/certclear.go:43, c0f382f2.
var certDirective = regexp.MustCompile(`(?m)^[ \t]*(ssl_certificate|ssl_certificate_key|ssl_trusted_certificate|ssl_client_certificate)[ \t]+([^;]+);`)
func main(){ if os.Args[1]=="path" {fmt.Print(normalizeXHTTPPath(os.Args[2]));return}; b,e:=os.ReadFile(os.Args[2]);if e!=nil{panic(e)}; for _,m:=range certDirective.FindAllStringSubmatch(string(b),-1){fmt.Printf("%s=%s\n",m[1],m[2])} }
