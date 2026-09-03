import mockAlerts from '../data/mockAlerts.json'

const API_BASE_URL = 'http://127.0.0.1:5000/api'

export function normalizeAlert(alert) {
  return {
    alert_id: alert.alert_id,
    timestamp: alert.timestamp,

    flow_id:
      alert.flow_id ||
      `flow-${alert.alert_id}`,

    source: {
      ip:
        alert.source?.ip ||
        alert.source_ip ||
        'Unknown',

      port:
        alert.source?.port ??
        alert.source_port ??
        0,
    },

    destination: {
      ip:
        alert.destination?.ip ||
        alert.destination_ip ||
        'Unknown',

      port:
        alert.destination?.port ??
        alert.destination_port ??
        0,
    },

    protocol:
      alert.protocol ||
      'Unknown',

    threat_class:
      alert.threat_class ||
      alert.threat ||
      'Unknown',

    confidence:
      Number(alert.confidence) || 0,

    severity:
      alert.severity ||
      'MEDIUM',

    detection_method:
      Array.isArray(alert.detection_method)
        ? alert.detection_method
        : ['BACKEND'],

    evidence:
      Array.isArray(alert.evidence)
        ? alert.evidence
        : Object.entries(alert.evidence || {}).map(
            ([key, value]) =>
              `${key}: ${value}`
          ),

    mitre: {
      tactic:
        alert.mitre?.tactic ||
        'Not specified',

      technique_id:
        alert.mitre?.technique_id ||
        alert.mitre?.technique ||
        null,

      technique_name:
        alert.mitre?.technique_name ||
        null,

      verify:
        alert.mitre?.verify ??
        true,
    },

    status:
      alert.status ||
      'NEW',
  }
}

export async function fetchAlerts() {
  const response = await fetch(
    `${API_BASE_URL}/alerts`
  )

  if (!response.ok) {
    throw new Error(
      `Failed to fetch alerts: ${response.status}`
    )
  }

  const data = await response.json()

  return (data.alerts || []).map(
    normalizeAlert
  )
}

export async function fetchAlertById(
  alertId
) {
  const response = await fetch(
    `${API_BASE_URL}/alerts/${alertId}`
  )

  if (!response.ok) {
    throw new Error(
      `Failed to fetch alert: ${response.status}`
    )
  }

  const data = await response.json()

  return normalizeAlert(data)
}

export async function fetchAlertStatistics() {
  const response = await fetch(
    `${API_BASE_URL}/stats`
  )

  if (!response.ok) {
    throw new Error(
      `Failed to fetch statistics: ${response.status}`
    )
  }

  return response.json()
}

export async function checkBackendHealth() {
  try {
    const response = await fetch(
      `${API_BASE_URL}/health`
    )

    if (!response.ok) {
      return false
    }

    const data = await response.json()

    return data.status === 'healthy'
  } catch {
    return false
  }
}

/*
 * SERVER-SENT EVENTS
 */

export function connectToAlertStream(
  onAlert,
  onStatusChange
) {
  const eventSource = new EventSource(
    `${API_BASE_URL}/stream`
  )

  eventSource.onopen = () => {
    console.log(
      'SSE connection established'
    )

    if (onStatusChange) {
      onStatusChange(true)
    }
  }

  eventSource.addEventListener(
    'connected',
    (event) => {
      console.log(
        'SSE connected:',
        event.data
      )
    }
  )

  eventSource.onmessage = (event) => {
    try {
      const alert = JSON.parse(
        event.data
      )

      onAlert(
        normalizeAlert(alert)
      )
    } catch (error) {
      console.error(
        'Failed to parse SSE alert:',
        error
      )
    }
  }

  eventSource.onerror = () => {
    console.warn(
      'SSE connection interrupted'
    )

    if (onStatusChange) {
      onStatusChange(false)
    }
  }

  return () => {
    eventSource.close()

    if (onStatusChange) {
      onStatusChange(false)
    }

    console.log(
      'SSE connection closed'
    )
  }
}

/*
 * MOCK DATA
 *
 * Kept temporarily as reference/fallback.
 */

export function getAlerts() {
  return mockAlerts.map(
    normalizeAlert
  )
}

export function getAlertById(
  alertId
) {
  const alert = mockAlerts.find(
    (item) =>
      item.alert_id === alertId
  )

  return alert
    ? normalizeAlert(alert)
    : undefined
}

export function getAlertsBySeverity(
  severity
) {
  const alerts = getAlerts()

  if (
    !severity ||
    severity === 'ALL'
  ) {
    return alerts
  }

  return alerts.filter(
    (alert) =>
      alert.severity === severity
  )
}

export function getAlertsByThreat(
  threatClass
) {
  const alerts = getAlerts()

  if (
    !threatClass ||
    threatClass === 'ALL'
  ) {
    return alerts
  }

  return alerts.filter(
    (alert) =>
      alert.threat_class ===
      threatClass
  )
}

export function getAlertStatistics() {
  const alerts = getAlerts()

  const totalAlerts =
    alerts.length

  const criticalAlerts =
    alerts.filter(
      (alert) =>
        alert.severity ===
        'CRITICAL'
    ).length

  const highAlerts =
    alerts.filter(
      (alert) =>
        alert.severity ===
        'HIGH'
    ).length

  const mediumAlerts =
    alerts.filter(
      (alert) =>
        alert.severity ===
        'MEDIUM'
    ).length

  const lowAlerts =
    alerts.filter(
      (alert) =>
        alert.severity ===
        'LOW'
    ).length

  const averageConfidence =
    totalAlerts > 0
      ? alerts.reduce(
          (sum, alert) =>
            sum +
            alert.confidence,
          0
        ) / totalAlerts
      : 0

  return {
    totalAlerts,
    criticalAlerts,
    highAlerts,
    mediumAlerts,
    lowAlerts,
    averageConfidence,
  }
}