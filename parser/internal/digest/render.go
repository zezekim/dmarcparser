package digest

import (
	"fmt"
	"html/template"
	"strings"
)

// render produces the inline-styled HTML body (email clients ignore <style>
// blocks, so every element carries its own style attribute).
func render(d *domainDigest, viewerURL string) (string, error) {
	delta := "no traffic last week"
	if d.Prev.Msgs > 0 {
		pct := (float64(d.This.Msgs) - float64(d.Prev.Msgs)) / float64(d.Prev.Msgs) * 100
		delta = fmt.Sprintf("%+.1f%% vs prior week", pct)
	}
	data := map[string]any{
		"D":         d,
		"Delta":     delta,
		"ThisRate":  fmt.Sprintf("%.1f%%", d.This.PassRate()),
		"PrevRate":  fmt.Sprintf("%.1f%%", d.Prev.PassRate()),
		"ViewerURL": strings.TrimSuffix(viewerURL, "/"),
		"Start":     d.Start.Format("2006-01-02"),
		"End":       d.End.AddDate(0, 0, -1).Format("2006-01-02"),
	}
	var b strings.Builder
	if err := tmpl.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

var tmpl = template.Must(template.New("digest").Parse(`<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#f4f5f7;font-family:Arial,Helvetica,sans-serif;color:#1f2933;">
<div style="max-width:640px;margin:0 auto;padding:24px;">
  <div style="background:#ffffff;border:1px solid #e0e4e8;border-radius:8px;padding:24px;">
    <h1 style="margin:0 0 4px 0;font-size:20px;color:#102a43;">DMARC weekly digest — {{.D.Domain}}</h1>
    <p style="margin:0 0 20px 0;font-size:13px;color:#627d98;">{{.Start}} to {{.End}} (UTC)</p>

    <table style="width:100%;border-collapse:collapse;margin-bottom:24px;">
      <tr>
        <td style="padding:12px;background:#f0f4f8;border-radius:6px;text-align:center;width:33%;">
          <div style="font-size:22px;font-weight:bold;color:#102a43;">{{.D.This.Msgs}}</div>
          <div style="font-size:12px;color:#627d98;">messages ({{.Delta}})</div>
        </td>
        <td style="width:8px;"></td>
        <td style="padding:12px;background:#f0f4f8;border-radius:6px;text-align:center;width:33%;">
          <div style="font-size:22px;font-weight:bold;color:#102a43;">{{.ThisRate}}</div>
          <div style="font-size:12px;color:#627d98;">aligned (prior week {{.PrevRate}})</div>
        </td>
        <td style="width:8px;"></td>
        <td style="padding:12px;background:#f0f4f8;border-radius:6px;text-align:center;width:33%;">
          <div style="font-size:22px;font-weight:bold;color:#102a43;">{{len .D.NewSenders}}</div>
          <div style="font-size:12px;color:#627d98;">new senders</div>
        </td>
      </tr>
    </table>

    {{if .D.TopFailing}}
    <h2 style="margin:0 0 8px 0;font-size:15px;color:#102a43;">Top failing sources</h2>
    <table style="width:100%;border-collapse:collapse;margin-bottom:24px;font-size:13px;">
      <tr style="background:#f0f4f8;">
        <th style="padding:6px 8px;text-align:left;border-bottom:1px solid #e0e4e8;">IP</th>
        <th style="padding:6px 8px;text-align:left;border-bottom:1px solid #e0e4e8;">PTR / class</th>
        <th style="padding:6px 8px;text-align:right;border-bottom:1px solid #e0e4e8;">Failing msgs</th>
      </tr>
      {{range .D.TopFailing}}
      <tr>
        <td style="padding:6px 8px;border-bottom:1px solid #f0f4f8;font-family:monospace;">{{.IP}}</td>
        <td style="padding:6px 8px;border-bottom:1px solid #f0f4f8;color:#627d98;">{{if .PTR}}{{.PTR}}{{end}}{{if .SenderClass}} ({{.SenderClass}}){{end}}</td>
        <td style="padding:6px 8px;border-bottom:1px solid #f0f4f8;text-align:right;color:#ab091e;">{{.Msgs}}</td>
      </tr>
      {{end}}
    </table>
    {{else}}
    <p style="margin:0 0 24px 0;font-size:13px;color:#3e8e41;">No failing sources this week.</p>
    {{end}}

    {{if .D.NewSenders}}
    <h2 style="margin:0 0 8px 0;font-size:15px;color:#102a43;">New senders</h2>
    <table style="width:100%;border-collapse:collapse;margin-bottom:24px;font-size:13px;">
      <tr style="background:#f0f4f8;">
        <th style="padding:6px 8px;text-align:left;border-bottom:1px solid #e0e4e8;">IP</th>
        <th style="padding:6px 8px;text-align:left;border-bottom:1px solid #e0e4e8;">PTR</th>
        <th style="padding:6px 8px;text-align:left;border-bottom:1px solid #e0e4e8;">First seen</th>
        <th style="padding:6px 8px;text-align:right;border-bottom:1px solid #e0e4e8;">Msgs (aligned)</th>
      </tr>
      {{range .D.NewSenders}}
      <tr>
        <td style="padding:6px 8px;border-bottom:1px solid #f0f4f8;font-family:monospace;">{{.IP}}</td>
        <td style="padding:6px 8px;border-bottom:1px solid #f0f4f8;color:#627d98;">{{.PTR}}</td>
        <td style="padding:6px 8px;border-bottom:1px solid #f0f4f8;">{{.FirstSeen.Format "2006-01-02"}}</td>
        <td style="padding:6px 8px;border-bottom:1px solid #f0f4f8;text-align:right;">{{.Msgs}} ({{.Aligned}})</td>
      </tr>
      {{end}}
    </table>
    {{end}}

    {{if .ViewerURL}}
    <p style="margin:0;font-size:13px;">
      <a href="{{.ViewerURL}}/domains/{{.D.Domain}}" style="color:#2680c2;">Open the full dashboard →</a>
    </p>
    {{end}}
  </div>
  <p style="margin:12px 0 0 0;font-size:11px;color:#9aa5b1;text-align:center;">
    Sent by dmarc-parser. Manage subscriptions via the parser API.
  </p>
</div>
</body></html>`))
