import "./waitforreconnection.css"
import { useTranslation } from 'react-i18next'


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

// const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

const WaitForReconnection = ({ opponent }) => {
    const { t } = useTranslation();

    return (
        <div className="reconnection-modal">
            <img src={`${BACKEND_URL}${opponent.avatar}`} alt="" className="opponent-avatar"/>
            <h2 className="opponent-username">{opponent.username}</h2>
            <h2 className="reconnection-title">{t('Waiting For Your Opponent to Get Back ...')}</h2>
        </div>
    );
}

export default WaitForReconnection;