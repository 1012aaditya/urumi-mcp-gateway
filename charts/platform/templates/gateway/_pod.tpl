{{/*
Pod template of the gateway Deployment (deployment.yaml).
  component   selector component label (`gateway`)
  image       "<repository>:<tag>"
  pullPolicy
Usage: include "platform.gatewayPodTemplate" (dict "ctx" $ "component" "gateway"
         "image" "…" "pullPolicy" "…") | nindent 4
*/}}
{{- define "platform.gatewayPodTemplate" -}}
{{- $ := .ctx }}
{{- $v := $.Values.gateway }}
{{- $pg := $.Values.postgres -}}
metadata:
  labels:
    {{- include "platform.labels" (dict "ctx" $ "component" .component) | nindent 4 }}
spec:
  automountServiceAccountToken: false
  securityContext:
    # node user of the node:22-alpine image.
    runAsUser: 1000
    runAsGroup: 1000
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: gateway
      image: {{ .image | quote }}
      imagePullPolicy: {{ .pullPolicy }}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      ports:
        - name: http
          containerPort: 8080
      env:
        - name: PORT
          value: "8080"
        - name: PUBLIC_ORIGIN
          value: {{ $v.publicOrigin | quote }}
        - name: COOKIE_SECURE
          value: {{ $v.cookieSecure | quote }}
        # Migrations run on start; concurrent starts are serialised by an advisory lock.
        - name: PGHOST
          value: {{ include "platform.postgresHost" $ | quote }}
        - name: PGPORT
          value: {{ $v.database.port | quote }}
        - name: PGUSER
          value: {{ $pg.user | quote }}
        - name: PGDATABASE
          value: {{ $pg.database | quote }}
        - name: PGPASSWORD
          valueFrom:
            secretKeyRef:
              name: {{ $.Values.secretName }}
              key: {{ $pg.secretKeys.password }}
        {{- range $name, $key := $v.secretKeys }}
        - name: {{ $name }}
          valueFrom:
            secretKeyRef:
              name: {{ $.Values.secretName }}
              key: {{ $key }}
        {{- end }}
        # In-cluster upstreams (woo-mcp, everything) resolve to private IPs; allow-list exactly
        # those Services. No wildcard: Postgres, MariaDB and WordPress stay blocked.
        {{- $upstreamHosts := list }}
        {{- range $component, $enabled := dict "woo-mcp" $.Values.wooMcp.enabled "everything" $.Values.everything.enabled }}
        {{- if $enabled }}
        {{- $upstreamHosts = append $upstreamHosts (printf "%s.%s.svc.cluster.local" (include "platform.componentName" (dict "ctx" $ "component" $component)) $.Release.Namespace) }}
        {{- end }}
        {{- end }}
        - name: UPSTREAM_ALLOWED_HOSTS
          value: {{ $v.upstreamAllowedHosts | default (join "," $upstreamHosts) | quote }}
        # Chat agent (C3). Optional: without the key the gateway runs and /api/chat answers 503.
        # Calls api.anthropic.com:443; no NetworkPolicy restricts gateway egress.
        - name: ANTHROPIC_API_KEY
          valueFrom:
            secretKeyRef:
              name: {{ $.Values.secretName }}
              key: {{ $v.chatSecretKey }}
              optional: true
        - name: CHAT_MODEL
          value: {{ $v.chatModel | quote }}
        {{- if $.Values.wooMcp.enabled }}
        # The internal woo-mcp upstream (W3) and the header secret it requires.
        - name: WOO_MCP_URL
          value: {{ include "platform.wooMcpUrl" $ | quote }}
        - name: WOO_MCP_SHARED_SECRET
          valueFrom:
            secretKeyRef:
              name: {{ $.Values.secretName }}
              key: {{ $.Values.wooMcp.secretKeys.sharedSecret }}
        {{- end }}
      # Startup waits for Postgres (up to 2 min) and runs migrations before listening.
      startupProbe:
        httpGet:
          path: /healthz
          port: http
        periodSeconds: 5
        timeoutSeconds: 3
        failureThreshold: 36
      readinessProbe:
        httpGet:
          path: /readyz
          port: http
        periodSeconds: 10
        timeoutSeconds: 3
        failureThreshold: 3
      livenessProbe:
        httpGet:
          path: /healthz
          port: http
        periodSeconds: 20
        timeoutSeconds: 3
        failureThreshold: 3
      resources:
        {{- toYaml $v.resources | nindent 8 }}
      volumeMounts:
        # The root filesystem is read-only; give Node a writable /tmp.
        - name: tmp
          mountPath: /tmp
  volumes:
    - name: tmp
      emptyDir:
        sizeLimit: 64Mi
{{- end }}

{{/*
podSelector for "this release's gateway pods". Used by the NetworkPolicies of the components only
the gateway may reach. Usage: include "platform.gatewayPeerSelector" . | nindent N
*/}}
{{- define "platform.gatewayPeerSelector" -}}
matchLabels:
  app.kubernetes.io/instance: {{ .Release.Name }}
  app.kubernetes.io/component: gateway
{{- end }}
