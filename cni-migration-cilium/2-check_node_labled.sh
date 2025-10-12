# verify all nodes are labelled correctly
LABELLED_NODE_COUNT=$(kubectl get node -l cni-plugin=aws -o json | jq '.items | length')
ALL_NODE_COUNT=$(kubectl get node -o json | jq '.items | length')

if [ ! "$LABELLED_NODE_COUNT" = "$ALL_NODE_COUNT" ]; then
    echo "Not all nodes labelled."
    echo "Labelled nodes: $LABELLED_NODE_COUNT, total: $ALL_NODE_COUNT"
    exit 1
fi

echo "All nodes are labelled."