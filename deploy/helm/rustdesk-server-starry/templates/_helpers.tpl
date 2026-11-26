{{- define "starry.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "starry.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "starry.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "starry.labels" -}}
helm.sh/chart: {{ include "starry.chart" . }}
{{ include "starry.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.version | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "starry.selectorLabels" -}}
app.kubernetes.io/name: {{ include "starry.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "starry.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "starry.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "starry.image" -}}
{{- $image := printf "%s:%s" .Values.image.repository .Values.version -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- $image -}}
{{- end -}}
{{- end -}}

{{- define "starry.pullSecrets" -}}
{{- with .Values.image.pullSecrets -}}
imagePullSecrets:
{{- toYaml . | nindent 0 }}
{{- end -}}
{{- end -}}

{{- define "starry.securityContext" -}}
securityContext:
  allowPrivilegeEscalation: {{ .Values.securityContext.allowPrivilegeEscalation }}
  readOnlyRootFilesystem: {{ .Values.securityContext.readOnlyRootFilesystem }}
  runAsNonRoot: {{ .Values.securityContext.runAsNonRoot }}
{{- end -}}

{{- /* Port part of the configured operations listen address. */ -}}
{{- define "starry.opsPort" -}}
{{- $address := .Values.hbbr.operations.listen -}}
{{- if contains ":" $address -}}
{{- (splitList ":" $address) | last -}}
{{- else -}}
{{- fail "hbbr.operations.listen must be host:port" -}}
{{- end -}}
{{- end -}}

{{- /* Host part of the configured operations listen address. */ -}}
{{- define "starry.opsHost" -}}
{{- $address := .Values.hbbr.operations.listen -}}
{{- if contains ":" $address -}}
{{- (splitList ":" $address) | initial | join ":" -}}
{{- else -}}
{{- fail "hbbr.operations.listen must be host:port" -}}
{{- end -}}
{{- end -}}
