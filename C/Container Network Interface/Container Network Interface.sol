apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: validator-net-policy
spec:
  podSelector:
    matchLabels:
      app: validator
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-gateway
        - podSelector:
            matchLabels:
              role: validator-relay
      ports:
        - protocol: TCP
          port: 30303 # P2P or RPC port
  egress:
    - to:
        - ipBlock:
            cidr: 10.0.0.0/8
      ports:
        - protocol: TCP
          port: 443
