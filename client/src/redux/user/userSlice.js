import { createSlice } from "@reduxjs/toolkit";

const initialState = {
    currentUser: null,
    error: null,
    loading: false,
};

const userSlice = createSlice({
    name: 'user',
    initialState,
    reducers: {
        signInstart: (state) => {
            // Ensure state exists, if not reset to initial state
            if (!state || typeof state !== 'object') {
                return { ...initialState, loading: true };
            }
            state.loading = true;
        },
        signInSuccess: (state, action) => {
            // Ensure state exists, if not reset to initial state
            if (!state || typeof state !== 'object') {
                return { ...initialState, currentUser: action.payload };
            }
            state.currentUser = action.payload;
            state.loading = false;
            state.error = null;
        },
        signInFailure: (state, action) => {
            // Ensure state exists, if not reset to initial state
            if (!state || typeof state !== 'object') {
                return { ...initialState, error: action.payload };
            }
            state.error = action.payload;
            state.loading = false;
        },
        updateUserstart: (state) => {
            if (!state || typeof state !== 'object') {
                return { ...initialState, loading: true };
            }
            state.loading = true;
        },
        updateUserSuccess: (state, action) => {
            if (!state || typeof state !== 'object') {
                return { ...initialState, currentUser: action.payload };
            }
            state.currentUser = action.payload;
            state.loading = false;
            state.error = null;
        },
        updateUserFailure: (state, action) => {
            if (!state || typeof state !== 'object') {
                return { ...initialState, error: action.payload };
            }
            state.error = action.payload;
            state.loading = false;
        },
        deleteUserstart: (state) => {
            if (!state || typeof state !== 'object') {
                return { ...initialState, loading: true };
            }
            state.loading = true;
        },
        deleteUserSuccess: (state, action) => {
            if (!state || typeof state !== 'object') {
                return { ...initialState };
            }
            state.currentUser = null;
            state.loading = false;
            state.error = null;
        },
        deleteUserFailure: (state, action) => {
            if (!state || typeof state !== 'object') {
                return { ...initialState, error: action.payload };
            }
            state.error = action.payload;
            state.loading = false;
        },
        signOutUserstart: (state) => {
            if (!state || typeof state !== 'object') {
                return { ...initialState, loading: true };
            }
            state.loading = true;
        },
        signOutUserSuccess: (state, action) => {
            if (!state || typeof state !== 'object') {
                return { ...initialState };
            }
            state.currentUser = null;
            state.loading = false;
            state.error = null;
        },
        signOutUserFailure: (state, action) => {
            if (!state || typeof state !== 'object') {
                return { ...initialState, error: action.payload };
            }
            state.error = action.payload;
            state.loading = false;
        },
    }
});

export const { 
    signInstart, 
    signInSuccess, 
    signInFailure,
    updateUserstart,
    updateUserFailure,
    updateUserSuccess,
    deleteUserstart,
    deleteUserSuccess,
    deleteUserFailure,
    signOutUserstart,
    signOutUserSuccess,
    signOutUserFailure
} = userSlice.actions;

export default userSlice.reducer;