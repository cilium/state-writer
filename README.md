# Cilium Datapath State Recovery

This program recovers endpoint state in case the Cilium on-disk state stored in
`/var/run/cilium/state` is partially or fully lost. It will reconstruct the
state for all currently active endpoints running on the node by querying the
`cilium-agent` API and synchronizing it to disk.

## Configuration

Edit `install/daemonset.yaml`:

* Set the value of the environment variable `CILIUM_VERSION` to the output of
  `cilium version`.

* If you want to force overwriting all state fules, define the environment
  variable `OVERWRITE_HEADERFILE` and set it to any value.

## Deployment

**Important:** Cilium must be running on all nodes. The state recovery will
only succeed on the nodes with a healthy Cilium agent.

Deploy the DaemonSet into the same namespace in which Cilium is running in:

     kubectl -n kube-system create -f install/daemonset.yaml

Check the log files of the deployed pods if needed:

     time="2020-05-14T16:17:58Z" level=info msg="Processing endpoint 3682"
     time="2020-05-14T16:17:58Z" level=info msg="Wrote /var/run/cilium/state/3682/lxc_config.h endpoint 3682"
     time="2020-05-14T16:17:58Z" level=info msg="Processing endpoint 1485"
     time="2020-05-14T16:17:58Z" level=info msg="Wrote /var/run/cilium/state/1485/lxc_config.h endpoint 1485"
