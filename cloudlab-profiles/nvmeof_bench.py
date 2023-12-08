"""CloudLab Profile to benchmark NVMEoF."""

# Import the Portal object.
import geni.portal as portal
# Import the ProtoGENI library.
import geni.rspec.pg as pg
# We use the URN library below.
import geni.urn as urn

from geni.rspec.emulab.emuext import setNoInterSwitchLinks

# Create a portal context.
pc = portal.Context()

# Create a Request object to start building the RSpec.
request = pc.makeRequestRSpec()

pc.defineParameter("NodeType", "Machine Type",
                   portal.ParameterType.STRING,
                   "c6525-100g")
params = pc.bindParameters()

if params.NodeType == "":
    perr = portal.ParameterError("Must provide a node type!",
                                 ["NodeType"])
    pc.reportError(perr, immediate=True)
    pass


# Host
node_0 = request.RawPC("nvmeof-host")
node_0.hardware_type = params.NodeType
node_0.disk_image = "urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU20-64-STD"
iface0 = node_0.addInterface("interface-0")

# Target
node_1 = request.RawPC("nvmeof-target")
node_1.hardware_type = params.NodeType
node_1.disk_image = "urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU20-64-STD"
iface1 = node_1.addInterface("interface-1")

# Link link-0
link_0 = request.Link("link-0")
link_0.Site("undefined")
link_0.addInterface(iface1)
link_0.addInterface(iface0)
link_0.setNoInterSwitchLinks()


# Print the RSpec to the enclosing page.
pc.printRequestRSpec(request)
