package net.floodlightcontroller.savi.analysis.web;

import org.projectfloodlight.openflow.protocol.OFStatsType;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.TableId;
import org.restlet.resource.Get;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.web.StatsReply;
import net.floodlightcontroller.savi.service.SAVIProviderService;

public class FlowResource extends FlowResourceBase{
	
	Logger log=LoggerFactory.getLogger(FlowResource.class);
	
	@Get("json")
	public StatsReply retrieve() {
		StatsReply result=new StatsReply();
		Object values=null;
		String tableIdStr=(String) getRequestAttributes().get(AnalysisWebRoutable.TABLE_ID);
		String switchIdStr=(String) getRequestAttributes().get(AnalysisWebRoutable.SWITCH_ID);
		DatapathId switchId=DatapathId.NONE;
		TableId tableId=TableId.NONE;
		
		SAVIProviderService saviProvider= (SAVIProviderService) getContext().getAttributes()
				.get(SAVIProviderService.class.getCanonicalName());
		
		if(switchIdStr.equalsIgnoreCase("all")) {
			switchId=DatapathId.NONE;
		}else {
			try {
				switchId=DatapathId.of(switchIdStr);
			} catch (Exception e) {
				log.info("解析交换机ID失败");
				return result;
			}
		}
		try {
			int id=Integer.parseInt(tableIdStr);
			tableId=TableId.of(id);
		} catch (Exception e) {
			log.info("解析tableId失败");
			return result;
		}
		if(switchId.equals(DatapathId.NONE)) {
			values=getSwitchStatistics(saviProvider.getPortsInBind().keySet(), tableId);
		}else {
			values = getSwitchStatistics(switchId, tableId);
		}
		
		result.setStatType(OFStatsType.FLOW);
		result.setDatapathId(switchId);
		result.setValues(values);
		
		return result;
	}
	
	
}
