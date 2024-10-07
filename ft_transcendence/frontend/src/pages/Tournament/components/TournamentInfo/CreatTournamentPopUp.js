import React, { useState, useContext } from 'react';
import { useEffect} from 'react';
import useAuth from '../../../../hooks/useAuth';
import useFetch from '../../../../hooks/useFetch';
import Select from 'react-select';
import './creatTournamentPopUp.css';
import History from '../../../../assets/MatchHistoryData';
import Icon from '../../../../assets/Icon/icons';
import PlayerSelectedItem from './PlayerSelectedItem';
import MainButton from '../../../../components/MainButton/MainButton';
import { UserContext } from '../../../../context/UserContext';
import CreatTournamentOnline from './CreatTournamentOnline';
import CreatTournamentOffline from './CreatTournamentOffline';
import { useTranslation } from 'react-i18next'


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;


const CreatTournamentPopUp = ({ isOpen, onClose})=> {
    const { auth }  = useAuth()
    const [selectedPlayers, setSelectedPlayers] = useState([]);
    const [selectedMap, setSelectedMap] = useState('');
    const [tournamentTitle, setTournamentTitle] = useState('');
    const [listFriend, setListFriend] = useState([]);
    const {data ,isLoading, error} = useFetch(`${BACKEND_URL}/user/friends/list/`)
    const [MapError, setMapError] = useState(false);
    const [NameError, setNameError] = useState(false);
    const [PlayersError, setPlayersError] = useState(false);
    const {updatetounament} = useContext(UserContext)
    const [tournamentOnlineOffline, setTournamentOnlineOffline] = useState('online')
    const { t } = useTranslation();



    useEffect(() => {
        if (data) {
          setListFriend(data);
        }
      }, [data]);

    const handleMapSelection = (mapName) => {
        setSelectedMap(mapName);
        setMapError(false)
    };

    const handlePlayerSelection = (selectedOptions) => {
        setSelectedPlayers(selectedOptions || []);
        setPlayersError(false)
    };


    const handleTitleChange = (event) => {
        setTournamentTitle(event.target.value);
        setNameError(false)
    };


    const handleCreateTournament = async () => {


        const postData = {
            tournament_name: tournamentTitle,
            tournament_map: selectedMap,
            invitedUsers: selectedPlayers.map(player => player.value),
        };

        if (!selectedMap){
            setMapError(true)
        }else{
            setMapError(false)
        }

        if (!tournamentTitle){
            setNameError(true)
        }else{
            setNameError(false)
        }

        if (selectedPlayers.length === 0 || selectedPlayers.length > 3){
            setPlayersError(true)
        }else{
            setPlayersError(false)
        }

        try {
            const response = await fetch(`${BACKEND_URL}/user/tournament/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.accessToken}`,
                    
                },
                body: JSON.stringify(postData)
            });
            if (response.ok) {
                onClose(); 
                const TournamentResponse = await fetch(`${BACKEND_URL}/user/tournament/`, {
                method: 'GET',
                    headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.accessToken}`
                    }
                });
                
                if (!TournamentResponse.ok) {
                    throw new Error('Network response was not ok');
                }
                const updatedTournamentData = await TournamentResponse.json();
                updatetounament(updatedTournamentData);
            } else {
                const errorData = await response.json();
                console.log('Error creating tournament: ' );
            }
        } catch (error) {

            console.error('Error creating tournament:', error);
        } 
    };

    const playerOptions = listFriend.map((player) => ({
        value: player.id,
        label: player.username,
        image: player.avatar
    }));


    const customStyles = {
        control: (provided, state) => ({
            ...provided,
            backgroundColor: '#1C1E27',
            borderColor: state.isFocused ? '#555' : '#1C1E27',
            color: '#FFF',
            boxShadow: state.isFocused ? '0 0 0 1px #555' : 'none',
            '&:hover': {
                borderColor: '#555',
            },
        }),
        menu: (provided) => ({
            ...provided,
            backgroundColor: '#1C1E27',
            color: '#FFF',
        }),
        option: (provided, state) => ({
            ...provided,
            backgroundColor: state.isFocused ? '#555' : '#1C1E27',
            color: '#FFF',
            '&:hover': {
                backgroundColor: '#555',
            },
        }),
        multiValue: (provided) => ({
            ...provided,
            backgroundColor: '#333',
            color: '#FFF',
        }),
        multiValueLabel: (provided) => ({
            ...provided,
            color: '#FFF',
        }),
        multiValueRemove: (provided) => ({
            ...provided,
            color: '#FFF',
            '&:hover': {
                backgroundColor: '#555',
                color: '#FFF',
            },
        }),
        placeholder: (provided) => ({
            ...provided,
            color: '#AAA',
        }),
        singleValue: (provided) => ({
            ...provided,
            color: '#FFF',
        }),
    };

    const [blockedUsers, setBlockedUsers] = useState([]);


    if (!isOpen) {
        return null;
    }

  return (
    <div className="modal-creatTournament">
      <div className="modal-creatTournamentPopup">
        <button className="modal-close-button" onClick={onClose}>&times;</button>
        <div className='TournamenrOnlineOffline'>
            <div className={`TournamentOF ${tournamentOnlineOffline === 'online' ? 'activeTournamenrOf' : ''}`} onClick={() => {
                setTournamentOnlineOffline('online')
            }}> 
                <p>{t('Online')}</p>
            </div>
            <div  className={`TournamentOF ${tournamentOnlineOffline === 'offline' ? 'activeTournamenrOf' : ''}`} onClick={() => {
                setTournamentOnlineOffline('offline')
            }}>
                <p>{t('Offline')}</p>
            </div>
        </div>
        {tournamentOnlineOffline === 'online' && <CreatTournamentOnline onClose={onClose}/>}
        {tournamentOnlineOffline === 'offline' && <CreatTournamentOffline onClose={onClose}/>}
      </div>
    </div>
  );
};

export default CreatTournamentPopUp;