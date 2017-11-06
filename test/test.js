contract('Conference',function(accounts){
	it("init conference settings should match",function(done){
		var conference=Conference.at(Conference.deployed_address);
		Conference.new({from:accounts[0]}).then(function(conference){
			conference.quota.call().then(function(quota){
				assert.equal(quota,500,"quota doesn't match");
			}).then(function(){
				return conference.numRegistrants.call();
			}).then(function(num){
				assert.equal(num,0,"Registrants should be zero");
				return conference.organizer.call();
			}).then(function(organizer){
				assert.equal(organizer,accounts[0],"owner doesn't match");
				done();
			}).catch(done);
		}).catch(done);
	});
});