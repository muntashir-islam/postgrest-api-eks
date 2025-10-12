for NODE in $(kubectl get node --output=jsonpath={.items..metadata.name}); do
    LABELLED=$(kubectl get node $NODE -o json | jq '.metadata.labels | has("cni-plugin")')
    if [ "$LABELLED" = "true" ]; then
        LABEL_VALUE=$(kubectl get node $NODE -o json | jq -r '.metadata.labels.cni-plugin')
        echo "Node $NODE already labelled: cni-plugin=$LABEL_VALUE"
    else
        kubectl label nodes $NODE cni-plugin=aws
    fi
done