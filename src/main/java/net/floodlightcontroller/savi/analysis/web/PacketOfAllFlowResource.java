package net.floodlightcontroller.savi.analysis.web;


import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.savi.analysis.IAnalysisService;

public class PacketOfAllFlowResource extends ServerResource {

	private static final Logger log = LoggerFactory.getLogger(PacketOfAllFlowResource.class);

	@Get("json")
	public Object retrieve(){
		IAnalysisService analysisService = (IAnalysisService) getContext().getAttributes().get(IAnalysisService.class.getCanonicalName());
		
		return analysisService.getAllPacketOfFlow();
	}
}
