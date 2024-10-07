import React, {useContext} from "react";
import style from "./block.module.css";
import blocked from "../../ChatAssets/blocked.json";
import Lottie from "lottie-react";
import { blockPopUpContext } from "../../usehooks/ChatContext";


const BlockPopUps = () => {
  const{blockpopUp, setblockpopUp} = useContext(blockPopUpContext)
  
  return ( blockpopUp ?
    <div className={style.blockHolder}>
      <h1 className={style.Blocktitle}>
        {" "}
        Oooops ! <span className={style.cantContact}> Can't Contact </span> this
        user !
      </h1>
      <div className={style.blockedanimation}>
      <Lottie animationData={blocked} />
      </div>
      
    </div>: ""
  );
};

export default BlockPopUps;
