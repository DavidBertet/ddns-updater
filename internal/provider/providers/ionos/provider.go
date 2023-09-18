package ionos

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"

	"github.com/qdm12/ddns-updater/internal/models"
	"github.com/qdm12/ddns-updater/internal/provider/constants"
	"github.com/qdm12/ddns-updater/internal/provider/errors"
	"github.com/qdm12/ddns-updater/internal/provider/headers"
	"github.com/qdm12/ddns-updater/internal/provider/utils"
	"github.com/qdm12/ddns-updater/pkg/ipextract"
	"github.com/qdm12/ddns-updater/pkg/publicip/ipversion"
)

type Provider struct {
	q         string
}

func New(data json.RawMessage) (p *Provider, err error) {
	extraSettings := struct {
		Q         string `json:"q"`
	}{}
	err = json.Unmarshal(data, &extraSettings)
	if err != nil {
		return nil, err
	}
	p = &Provider{
		q:         extraSettings.Q,
	}
	err = p.isValid()
	if err != nil {
		return nil, err
	}
	return p, nil
}

var qRegex = regexp.MustCompile(`^.+$`)

func (p *Provider) isValid() error {
	if !qRegex.MatchString(p.q) {
		return fmt.Errorf("%w: q %q does not match regex %q",
			errors.ErrQNotValid, p.q, qRegex)
	}
	return nil
}

func (p *Provider) String() string {
	return utils.ToString("ionos.com", "@", constants.Ionos, p.IPVersion())
}

func (p *Provider) Domain() string {
	return "ionos.com"
}

func (p *Provider) Host() string {
	return "@"
}

func (p *Provider) IPVersion() ipversion.IPVersion {
	return ipversion.IP4
}

func (p *Provider) Proxied() bool {
	return false
}

func (p *Provider) BuildDomainName() string {
	return "ionos.com"
}

func (p *Provider) HTML() models.HTMLRow {
	return models.HTMLRow{
		Domain:    fmt.Sprintf("<a href=\"http://%s\">%s</a>", p.BuildDomainName(), p.BuildDomainName()),
		Host:      p.Host(),
		Provider:  "<a href=\"https://ionos.com\">Ionos</a>",
		IPVersion: p.IPVersion().String(),
	}
}

func (p *Provider) Update(ctx context.Context, client *http.Client, ip netip.Addr) (newIP netip.Addr, err error) {
	u := url.URL{
		Scheme: "https",
		Host:   "ipv4.api.hosting.ionos.com",
		Path:   "/dns/v1/dyndns",
	}
	values := url.Values{}
	values.Set("q", p.q)

	u.RawQuery = values.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("creating http request: %w", err)
	}
	headers.SetUserAgent(request)

	response, err := client.Do(request)
	if err != nil {
		return netip.Addr{}, err
	}
	defer response.Body.Close()

	b, err := io.ReadAll(response.Body)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("reading response body: %w", err)
	}
	s := string(b)

	if response.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("%w: %d: %s",
			errors.ErrHTTPStatusNotValid, response.StatusCode, utils.ToSingleLine(s))
	}

	const minChars = 2
	switch {
	case len(s) < minChars:
		return netip.Addr{}, fmt.Errorf("%w: %s", errors.ErrResponseTooShort, s)
	case s[0:minChars] == "KO":
		return netip.Addr{}, fmt.Errorf("%w", errors.ErrAuth)
	case s[0:minChars] == "OK":
		ips := ipextract.IPv4(s)
		if len(ips) == 0 {
			return netip.Addr{}, fmt.Errorf("%w", errors.ErrReceivedNoIP)
		}
		newIP = ips[0]
		if newIP.Compare(ip) != 0 {
			return netip.Addr{}, fmt.Errorf("%w: sent ip %s to update but received %s",
				errors.ErrIPReceivedMismatch, ip, newIP)
		}
		return newIP, nil
	default:
		return netip.Addr{}, fmt.Errorf("%w: %s", errors.ErrUnknownResponse, s)
	}
}
