import React, {useState, useEffect} from "react"
import { SuccessToast } from "../../../components/ReactToastify/SuccessToast";
import { ErrorToast } from "../../../components/ReactToastify/ErrorToast";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

export  function useGetBlockDetails(ChatPartner, auth){
    const [blockRelation, setblockRelation] = useState(false);

    useEffect(() => {
        const fetchBlockStatus = async () => {
            const url = `${BACKEND_URL}/user/${ChatPartner.id}/block-unblock/`;
            try {
                const response = await fetch(url, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${auth.accessToken}`,
                    },
                });
                if (response.ok) {
                    const data = await response.json();
                    setblockRelation(data.is_blocked);
                } else {
                    ErrorToast(`Error : ${response.statusText}`);
                }
            } catch (error) {
                ErrorToast(`Error :  ${error}`);
            }
            finally {}
        };
        if(ChatPartner){
          fetchBlockStatus();
        }
      }, [ChatPartner, auth.accessToken]);

      return {
        blockRelation,
      }
}