"""Two nodes. One optane server and one client of some type."""

# Import the Portal object.
import geni.portal as portal
# Import the ProtoGENI library.
import geni.rspec.pg as pg
# We use the URN library below.
import geni.urn as urn
# Emulab extension
import geni.rspec.emulab

# Create a portal context.
pc = portal.Context()

# Create a Request object to start building the RSpec.
request = pc.makeRequestRSpec()

# Define a parameter to set the node. Needs to be a URN.
pc.defineParameter("OptaneNodeID", "Optane Node ID",
                   portal.ParameterType.STRING,
                   "urn:publicid:IDN+utah.cloudlab.us+node+flex02")
pc.defineParameter("ClientNodeType", "Client Node Machine Type",
                   portal.ParameterType.STRING,
                   "c6525-100g")
params = pc.bindParameters()

if params.OptaneNodeID == "":
    perr = portal.ParameterError("Must provide an ID for the Optane node!",
                                 ['OptaneNodeID'])
    pc.reportError(perr, immediate=True)
    pass
if params.ClientNodeType == "":
    perr = portal.ParameterError("Must provide a node type for the client!",
                                 ['ClientNodeType'])
    pc.reportError(perr, immediate=True)
    pass
if not urn.Base.isValidURN(params.OptaneNodeID):
    perr = portal.ParameterError("Not a valid node URN!", ['NodeID1'])
    pc.reportError(perr, immediate=True)
    pass


# Optane node
node_0 = request.RawPC("optane-node")
node_0.component_id = params.OptaneNodeID
node_0.disk_image = "urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU20-64-STD"
iface0 = node_0.addInterface('interface-0')

# Client node
node_1 = request.RawPC("client-node")
node_1.hardware_type = params.ClientNodeType
node_1.disk_image = "urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU20-64-STD"
iface1 = node_1.addInterface('interface-1')

# Link link-0
link_0 = request.Link('link-0')
link_0.Site('undefined')
link_0.addInterface(iface1)
link_0.addInterface(iface0)


# Print the RSpec to the enclosing page.
pc.printRequestRSpec(request)
