package net.floodlightcontroller.savi.analysis;

public class PacketOfFlow {
	//上一个时间窗口，验证通过的数据包数
	long passNum;
	//上一个时间窗口，验证失败被丢弃的数据包数
	long lossNum;
	//累计验证通过的数据包数
	long accumulatePassNum;
	//累计验证失败被丢弃的数据包数
	long accumulateLossNum;
	//上一个时间窗口的丢包率
	double lossRate;
	//累计丢包率
	double accumulateLossRate;
	
	public double getlossRate() {
		return lossRate;
	}

	public PacketOfFlow(long passNum, long lossNum, long accumulatePassNum, long accumulateLossNum, double lossRate,
			double accumulateLossRate) {
		super();
		this.passNum = passNum;
		this.lossNum = lossNum;
		this.accumulatePassNum = accumulatePassNum;
		this.accumulateLossNum = accumulateLossNum;
		this.lossRate = lossRate;
		this.accumulateLossRate = accumulateLossRate;
	}

	public long getPassNum() {
		return passNum;
	}

	public void setPassNum(long passNum) {
		this.passNum = passNum;
	}

	public long getLossNum() {
		return lossNum;
	}

	public void setLossNum(long lossNum) {
		this.lossNum = lossNum;
	}

	public long getAccumulatePassNum() {
		return accumulatePassNum;
	}

	public void setAccumulatePassNum(long accumulatePassNum) {
		this.accumulatePassNum = accumulatePassNum;
	}

	public long getAccumulateLossNum() {
		return accumulateLossNum;
	}

	public void setAccumulateLossNum(long accumulateLossNum) {
		this.accumulateLossNum = accumulateLossNum;
	}

	public double getLossRate() {
		return lossRate;
	}

	public void setLossRate(double lossRate) {
		this.lossRate = lossRate;
	}

	public double getAccumulateLossRate() {
		return accumulateLossRate;
	}

	public void setAccumulateLossRate(double accumulateLossRate) {
		this.accumulateLossRate = accumulateLossRate;
	}
	
}
