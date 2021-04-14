@load base/frameworks/sumstats
event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="response_404", $apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="response_all", $apply=set(SumStats::SUM));
    local r3 = SumStats::Reducer($stream="response_unique", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="404response",
                      $epoch=10mins,
                      $reducers=set(r1,r2,r3),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                      {
                        local n1 = result["response_404"];
                        local n2 = result["response_all"];
                        local n3 = result["response_unique"];
                        if(n1$sum>2){
                             if(n1$sum/n2$sum>0.2){
                                    if(n3$sum/n1$sum>0.5){
                                        print fmt("%s is a scanner with %d scan attemps on %d urls", 
                        			key$host, n1$num, n3$unique);
                                     }
                             }
                        }
                       }]);
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
          SumStats::observe("response_all",  [$host=c$id$orig_h],  [$num=1]);
          if(code==404){
          SumStats::observe("response_404",  [$host=c$id$orig_h],  [$num=1]);
          SumStats::observe("response_unique",  [$host=c$id$orig_h],  [$str=c$http$uri]);
          }
          

    }