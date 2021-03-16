package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/mattn/go-isatty"
)

var (
	dst        net.IP
	src        net.IP
	dstPort    layers.UDPPort
	srcPort    layers.UDPPort
	format     string
	isConvert  bool
	isTerminal = isatty.IsTerminal(os.Stdin.Fd())
)

const (
	rfc3164Layout = time.Stamp
	rfc3164Regexp = `[A-Z][a-z][a-z]\s+\d+\s\d\d:\d\d:\d\d`

	rfc5424Layout = time.RFC3339
	rfc5424Regexp = `\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(Z|-\d\d:\d\d|\+\d\d:\d\d)`

	rfc5424TenMilliLayout = "2006-01-02T15:04:05.00Z07:00"
	rfc5424TenMilliRegexp = `\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d(Z|-\d\d:\d\d|\+\d\d:\d\d)`

	rfc5424MilliLayout = "2006-01-02T15:04:05.000Z07:00"
	rfc5424MilliRegexp = `\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d(Z|-\d\d:\d\d|\+\d\d:\d\d)`

	rfc5424MicroLayout = "2006-01-02T15:04:05.000000Z07:00"
	rfc5424MicroRegexp = `\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\d\d\d(Z|-\d\d:\d\d|\+\d\d:\d\d)`
)

const formatList = `
Format:
  rfc3164         : Jan _2 15:04:05
  rfc5424         : 2006-01-02T15:04:05Z07:00
  rfc5424TenMilli : 2006-01-02T15:04:05.00Z07:00
  rfc5424Milli    : 2006-01-02T15:04:05.000Z07:00
  rfc5424Micro    : 2006-01-02T15:04:05.000000Z07:00
`

func selectFormat(name string) (string, string, error) {
	switch name {
	case "rfc3164":
		return rfc3164Layout, rfc3164Regexp, nil
	case "rfc5424":
		return rfc5424Layout, rfc5424Regexp, nil
	case "rfc5424TenMilli":
		return rfc5424TenMilliLayout, rfc5424TenMilliRegexp, nil
	case "rfc5424Milli":
		return rfc5424MilliLayout, rfc5424MilliRegexp, nil
	case "rfc5424Micro":
		return rfc5424MicroLayout, rfc5424MicroRegexp, nil
	default:
		return "", "", errors.New("Please specify the correct format")
	}
}

func run() int {
	_layout, _regexp, err := selectFormat(format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Error] %s\n", err)
		return 1
	}

	_re := regexp.MustCompile(_regexp)
	conn, err := Open(src.To4(), dst.To4(), srcPort, dstPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Error] %s\n", err)
		return 1
	}
	defer conn.Close()

	fmt.Fprintf(os.Stdout, "%s:%s => %s:%s\n", conn.srcIP, conn.srcPort, conn.dstIP, conn.dstPort)
	if isTerminal {
		fmt.Fprint(os.Stdout, "[Type Ctrl-D to end input]\n")
	}
	scanner := bufio.NewScanner(os.Stdin)

	var t time.Time
	for scanner.Scan() {
		data := scanner.Text()
		date := _re.FindString(data)
		_t, err := time.Parse(_layout, date)

		if err != nil {
			fmt.Fprint(os.Stderr, "[Error] Failed to parse time format\n")
			continue
		}

		if !isTerminal && !t.IsZero() {
			time.Sleep(_t.Sub(t))
		}

		if isConvert {
			data = strings.Replace(data, date, time.Now().Format(_layout), 1)
		}

		fmt.Fprintf(conn, "%s\n", data)
		if !isTerminal {
			fmt.Fprintf(os.Stdout, "%s\n", data)
		}
		t = _t
	}
	return 0
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage:
  %s [option] dest-address [src-address]

Option:
`, flag.CommandLine.Name())
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, formatList)
	}

	var d, s uint
	flag.UintVar(&d, "d", 514, "Specify the destination port")
	flag.UintVar(&s, "s", 514, "Specify the source port")
	flag.BoolVar(&isConvert, "c", false, "Convert syslog's timestamp to the current timestamp")
	flag.StringVar(&format, "f", "rfc3164", "Specify the syslog format")
	flag.Parse()

	dst = net.ParseIP(flag.Arg(0))
	if dst == nil {
		fmt.Fprint(os.Stderr, "[Error] Please specify the correct destination address\n")
		os.Exit(1)
	}

	if flag.Arg(1) == "" {
		src = nil
	} else {
		src = net.ParseIP(flag.Arg(1))
		if src == nil {
			fmt.Fprint(os.Stderr, "[Error] Please specify the correct source address\n")
			os.Exit(1)
		}
	}
	dstPort = layers.UDPPort(d)
	srcPort = layers.UDPPort(s)

	os.Exit(run())
}
