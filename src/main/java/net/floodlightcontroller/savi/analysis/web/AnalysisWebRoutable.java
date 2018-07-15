package net.floodlightcontroller.savi.analysis.web;

import org.restlet.Context;
import org.restlet.routing.Router;

import net.floodlightcontroller.restserver.RestletRoutable;
import net.floodlightcontroller.savi.rest.ChangeTableResource;

public class AnalysisWebRoutable implements RestletRoutable {

	protected static final String ENABLE_STR = "enable";
	protected static final String DISABLE_STR = "disable";
	protected static final String DPID_STR = "dpid";
	protected static final String PORT_STR = "port";
	protected static final String STAGE_INIT = "init";
	protected static final String PLAN_TYPE = "plan";
	
	@Override
	public Router getRestlet(Context context) {
		Router router=new Router(context);
		router.attach("/test", TestResource.class);
		router.attach("/status/init",StatusResource.class);
		router.attach("/enable/json",ConfigureResource.class);
		router.attach("/disable/json",ConfigureResource.class);
		router.attach("/packets/{"+ DPID_STR + "}/{" + PORT_STR + "}/json" , InPacketsResource.class);
		router.attach("/packets/json" , PacketsResource.class);
		router.attach("/packets/drop/{"+ DPID_STR+ "}/{"+ PORT_STR +"}/json" , PacketOfFlowResource.class);
		router.attach("/packets/drop/json" , PacketOfAllFlowResource.class);
		router.attach("/ports/json" , PortSetResource.class);
		router.attach("/table/change/json", ChangeTableResource.class);
		router.attach("/plan/{" + PLAN_TYPE +"}/json" , PlanResource.class);

		router.attach("/traffic/get/out", SpecifyOutflowResource.class);
		router.attach("/traffic/update/out", SpecifyOutflowResource.class);
		router.attach("/traffic/get/in", InTrafficResource.class);
		router.attach("/traffic/update/in", InTrafficResource.class);
		
		
		return router;                                                            
	}

	@Override
	public String basePath() {
		return "/analysis";
	}

}
