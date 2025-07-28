"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Settings, Shield, Network, Bell, Database, Key, Monitor, Save, RefreshCw, CheckCircle } from "lucide-react"

export default function SettingsPage() {
  const [settings, setSettings] = useState({
    // General Settings
    organizationName: "Security Corp",
    timezone: "UTC",
    language: "en",

    // Security Settings
    sessionTimeout: "30",
    mfaRequired: true,
    passwordPolicy: "strong",

    // Scanning Settings
    maxConcurrentScans: "5",
    scanTimeout: "300",
    defaultScanPorts: "1-1000",

    // Notification Settings
    emailNotifications: true,
    slackIntegration: false,
    webhookUrl: "",

    // API Settings
    apiRateLimit: "100",
    apiKeyExpiry: "90",

    // Database Settings
    backupFrequency: "daily",
    retentionPeriod: "365",
  })

  const [saved, setSaved] = useState(false)

  const handleSave = () => {
    // Simulate saving settings
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
  }

  const handleReset = () => {
    // Reset to default values
    setSettings({
      organizationName: "Security Corp",
      timezone: "UTC",
      language: "en",
      sessionTimeout: "30",
      mfaRequired: true,
      passwordPolicy: "strong",
      maxConcurrentScans: "5",
      scanTimeout: "300",
      defaultScanPorts: "1-1000",
      emailNotifications: true,
      slackIntegration: false,
      webhookUrl: "",
      apiRateLimit: "100",
      apiKeyExpiry: "90",
      backupFrequency: "daily",
      retentionPeriod: "365",
    })
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <div>
        <h1 className="text-2xl sm:text-3xl font-bold text-foreground mb-2">Settings</h1>
        <p className="text-muted-foreground text-sm sm:text-base">Configure system preferences and security policies</p>
      </div>

      {saved && (
        <Alert className="bg-green-100 dark:bg-green-900 border border-green-300 dark:border-green-700">
          <CheckCircle className="h-4 w-4 text-green-600 dark:text-green-200" />
          <AlertDescription className="text-green-700 dark:text-green-200">Settings have been saved successfully!</AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 sm:gap-6">
        {/* General Settings */}
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-foreground flex items-center text-lg sm:text-xl">
              <Settings className="h-4 w-4 sm:h-5 sm:w-5 mr-2" />
              General Settings
            </CardTitle>
            <CardDescription className="text-muted-foreground text-sm">Basic system configuration</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="orgName" className="text-foreground text-sm">
                Organization Name
              </Label>
              <Input
                id="orgName"
                value={settings.organizationName}
                onChange={(e) => setSettings({ ...settings, organizationName: e.target.value })}
                className="bg-secondary border-border text-foreground text-sm sm:text-base"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="timezone" className="text-foreground text-sm">
                  Timezone
                </Label>
                <Select
                  value={settings.timezone}
                  onValueChange={(value) => setSettings({ ...settings, timezone: value })}
                >
                  <SelectTrigger className="bg-secondary border-border text-foreground text-sm">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-secondary border-border">
                    <SelectItem value="UTC">UTC</SelectItem>
                    <SelectItem value="EST">Eastern Time</SelectItem>
                    <SelectItem value="PST">Pacific Time</SelectItem>
                    <SelectItem value="GMT">Greenwich Mean Time</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="language" className="text-foreground text-sm">
                  Language
                </Label>
                <Select
                  value={settings.language}
                  onValueChange={(value) => setSettings({ ...settings, language: value })}
                >
                  <SelectTrigger className="bg-secondary border-border text-foreground text-sm">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-secondary border-border">
                    <SelectItem value="en">English</SelectItem>
                    <SelectItem value="es">Spanish</SelectItem>
                    <SelectItem value="fr">French</SelectItem>
                    <SelectItem value="de">German</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Security Settings */}
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-foreground flex items-center text-lg sm:text-xl">
              <Shield className="h-4 w-4 sm:h-5 sm:w-5 mr-2" />
              Security Settings
            </CardTitle>
            <CardDescription className="text-muted-foreground text-sm">Authentication and access control</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="sessionTimeout" className="text-foreground text-sm">
                Session Timeout (minutes)
              </Label>
              <Input
                id="sessionTimeout"
                type="number"
                value={settings.sessionTimeout}
                onChange={(e) => setSettings({ ...settings, sessionTimeout: e.target.value })}
                className="bg-secondary border-border text-foreground text-sm sm:text-base"
              />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label className="text-foreground text-sm">Multi-Factor Authentication</Label>
                <p className="text-muted-foreground text-xs">Require MFA for all users</p>
              </div>
              <Switch
                checked={settings.mfaRequired}
                onCheckedChange={(checked) => setSettings({ ...settings, mfaRequired: checked })}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="passwordPolicy" className="text-foreground text-sm">
                Password Policy
              </Label>
              <Select
                value={settings.passwordPolicy}
                onValueChange={(value) => setSettings({ ...settings, passwordPolicy: value })}
              >
                <SelectTrigger className="bg-secondary border-border text-foreground text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-secondary border-border">
                  <SelectItem value="basic">Basic (8+ characters)</SelectItem>
                  <SelectItem value="strong">Strong (12+ chars, mixed case, numbers)</SelectItem>
                  <SelectItem value="complex">Complex (16+ chars, symbols required)</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        </Card>

        {/* Scanning Settings */}
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-foreground flex items-center text-lg sm:text-xl">
              <Network className="h-4 w-4 sm:h-5 sm:w-5 mr-2" />
              Scanning Configuration
            </CardTitle>
            <CardDescription className="text-muted-foreground text-sm">Default scanning parameters</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="maxScans" className="text-foreground text-sm">
                  Max Concurrent Scans
                </Label>
                <Input
                  id="maxScans"
                  type="number"
                  value={settings.maxConcurrentScans}
                  onChange={(e) => setSettings({ ...settings, maxConcurrentScans: e.target.value })}
                  className="bg-secondary border-border text-foreground text-sm sm:text-base"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="scanTimeout" className="text-foreground text-sm">
                  Scan Timeout (seconds)
                </Label>
                <Input
                  id="scanTimeout"
                  type="number"
                  value={settings.scanTimeout}
                  onChange={(e) => setSettings({ ...settings, scanTimeout: e.target.value })}
                  className="bg-secondary border-border text-foreground text-sm sm:text-base"
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="defaultPorts" className="text-foreground text-sm">
                Default Port Range
              </Label>
              <Input
                id="defaultPorts"
                value={settings.defaultScanPorts}
                onChange={(e) => setSettings({ ...settings, defaultScanPorts: e.target.value })}
                placeholder="1-1000,3389,5432"
                className="bg-secondary border-border text-foreground text-sm sm:text-base"
              />
            </div>
          </CardContent>
        </Card>

        {/* Notification Settings */}
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-foreground flex items-center text-lg sm:text-xl">
              <Bell className="h-4 w-4 sm:h-5 sm:w-5 mr-2" />
              Notifications
            </CardTitle>
            <CardDescription className="text-muted-foreground text-sm">Alert and notification preferences</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label className="text-foreground text-sm">Email Notifications</Label>
                <p className="text-muted-foreground text-xs">Send scan results via email</p>
              </div>
              <Switch
                checked={settings.emailNotifications}
                onCheckedChange={(checked) => setSettings({ ...settings, emailNotifications: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label className="text-foreground text-sm">Slack Integration</Label>
                <p className="text-muted-foreground text-xs">Send alerts to Slack channels</p>
              </div>
              <Switch
                checked={settings.slackIntegration}
                onCheckedChange={(checked) => setSettings({ ...settings, slackIntegration: checked })}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="webhook" className="text-foreground text-sm">
                Webhook URL
              </Label>
              <Input
                id="webhook"
                value={settings.webhookUrl}
                onChange={(e) => setSettings({ ...settings, webhookUrl: e.target.value })}
                placeholder="https://hooks.slack.com/..."
                className="bg-secondary border-border text-foreground text-sm sm:text-base"
              />
            </div>
          </CardContent>
        </Card>

        {/* API Settings */}
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-foreground flex items-center text-lg sm:text-xl">
              <Key className="h-4 w-4 sm:h-5 sm:w-5 mr-2" />
              API Configuration
            </CardTitle>
            <CardDescription className="text-muted-foreground text-sm">API access and rate limiting</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="rateLimit" className="text-foreground text-sm">
                  Rate Limit (requests/hour)
                </Label>
                <Input
                  id="rateLimit"
                  type="number"
                  value={settings.apiRateLimit}
                  onChange={(e) => setSettings({ ...settings, apiRateLimit: e.target.value })}
                  className="bg-secondary border-border text-foreground text-sm sm:text-base"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="keyExpiry" className="text-foreground text-sm">
                  API Key Expiry (days)
                </Label>
                <Input
                  id="keyExpiry"
                  type="number"
                  value={settings.apiKeyExpiry}
                  onChange={(e) => setSettings({ ...settings, apiKeyExpiry: e.target.value })}
                  className="bg-secondary border-border text-foreground text-sm sm:text-base"
                />
              </div>
            </div>

            <div className="p-3 bg-secondary rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-foreground text-sm">Current API Key</span>
                <Badge variant="outline" className="border-green-600 text-green-400 text-xs">
                  Active
                </Badge>
              </div>
              <code className="text-muted-foreground text-xs font-mono break-all">pk_live_51H7qABC123...xyz789</code>
            </div>
          </CardContent>
        </Card>

        {/* Database Settings */}
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-foreground flex items-center text-lg sm:text-xl">
              <Database className="h-4 w-4 sm:h-5 sm:w-5 mr-2" />
              Database & Backup
            </CardTitle>
            <CardDescription className="text-muted-foreground text-sm">Data retention and backup policies</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="backupFreq" className="text-foreground text-sm">
                  Backup Frequency
                </Label>
                <Select
                  value={settings.backupFrequency}
                  onValueChange={(value) => setSettings({ ...settings, backupFrequency: value })}
                >
                  <SelectTrigger className="bg-secondary border-border text-foreground text-sm">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-secondary border-border">
                    <SelectItem value="hourly">Hourly</SelectItem>
                    <SelectItem value="daily">Daily</SelectItem>
                    <SelectItem value="weekly">Weekly</SelectItem>
                    <SelectItem value="monthly">Monthly</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="retention" className="text-foreground text-sm">
                  Retention Period (days)
                </Label>
                <Input
                  id="retention"
                  type="number"
                  value={settings.retentionPeriod}
                  onChange={(e) => setSettings({ ...settings, retentionPeriod: e.target.value })}
                  className="bg-secondary border-border text-foreground text-sm sm:text-base"
                />
              </div>
            </div>

            <div className="p-3 bg-secondary rounded-lg">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-foreground text-sm">Last Backup</p>
                  <p className="text-muted-foreground text-xs">2024-01-15 03:00:00 UTC</p>
                </div>
                <Badge variant="outline" className="border-green-600 text-green-400 text-xs">
                  Success
                </Badge>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Action Buttons */}
      <div className="flex flex-col sm:flex-row gap-3 sm:gap-4 pt-4">
        <Button onClick={handleSave} className="bg-green-600 hover:bg-green-700 text-sm sm:text-base">
          <Save className="h-4 w-4 mr-2" />
          Save Settings
        </Button>
        <Button
          onClick={handleReset}
          variant="outline"
          className="border-border text-foreground hover:bg-muted text-sm sm:text-base bg-transparent"
        >
          <RefreshCw className="h-4 w-4 mr-2" />
          Reset to Defaults
        </Button>
      </div>


    </div>
  )
}
